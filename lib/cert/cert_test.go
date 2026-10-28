package cert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/oxgen1/sso/lib/httpsig"
)

var testNow = time.Unix(1_800_000_000, 0)

const (
	testService = "statusd"
	testRemote  = "10.100.0.7:51000"
)

func newKey(t testing.TB, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newTestCA(t testing.TB, name string) *CA {
	t.Helper()
	key := newKey(t, elliptic.P256())
	der, err := NewCA(name, key, testNow.Add(-24*time.Hour), testNow.Add(365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := NewCAFromDER(der, key)
	if err != nil {
		t.Fatal(err)
	}
	ca.Now = func() time.Time { return testNow }
	return ca
}

func testClaims(t testing.TB) Claims {
	return Claims{
		User:     "jack",
		Services: []string{testService, "grafana"},
		Roles:    []string{"admin", "write"},
		Passkeys: []Passkey{
			{ID: []byte("yubikey-1"), Key: &newKey(t, elliptic.P256()).PublicKey},
			{ID: []byte("phone"), Key: &newKey(t, elliptic.P256()).PublicKey},
		},
		Sources: []netip.Prefix{netip.MustParsePrefix("10.100.0.0/24"), netip.MustParsePrefix("fd00:100::/64")},
	}
}

// fixture is a CA, a client key, a certificate template Issue would sign, and
// what Verify is called with. A mutation changes any of them before build.
type fixture struct {
	t      testing.TB
	ca     *CA
	key    *ecdsa.PrivateKey
	claims Claims

	tmpl   *x509.Certificate
	pub    any               // the certificate's key
	parent *x509.Certificate // the issuer
	signer crypto.Signer     // the issuer's key

	der   []byte // set by build unless a mutation set it
	keyID string // the serial unless a mutation set it
	r     *http.Request
	v     *Verifier
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	f := &fixture{t: t, ca: newTestCA(t, "farm1 SSO CA"), key: newKey(t, elliptic.P256()), claims: testClaims(t)}
	var err error
	if f.tmpl, err = f.ca.template(&f.key.PublicKey, f.claims); err != nil {
		t.Fatal(err)
	}
	f.pub, f.parent, f.signer = &f.key.PublicKey, f.ca.Cert, f.ca.Key
	f.r = httptest.NewRequest(http.MethodGet, "http://farm-1:9200/v1/status", nil)
	f.r.RemoteAddr = testRemote
	if f.v, err = NewVerifier(f.ca.Cert.Raw, testService); err != nil {
		t.Fatal(err)
	}
	f.v.Now = func() time.Time { return testNow }
	return f
}

func (f *fixture) build() {
	f.t.Helper()
	if f.der != nil {
		return
	}
	var err error
	if f.der, err = x509.CreateCertificate(rand.Reader, f.tmpl, f.parent, f.pub, f.signer); err != nil {
		f.t.Fatal(err)
	}
	if f.keyID == "" {
		x, err := x509.ParseCertificate(f.der)
		if err != nil {
			f.t.Fatal(err)
		}
		f.keyID = x.SerialNumber.Text(16)
	}
}

func (f *fixture) verify() (*Cert, error) {
	f.build()
	_, c, err := f.v.Verify(f.r, f.der, f.keyID)
	return c, err
}

// setExt replaces (or with value nil, removes) an extension in the template.
func (f *fixture) setExt(id asn1.ObjectIdentifier, critical bool, value []byte) {
	f.tmpl.ExtraExtensions = slices.DeleteFunc(f.tmpl.ExtraExtensions, func(e pkix.Extension) bool { return e.Id.Equal(id) })
	if value != nil {
		f.tmpl.ExtraExtensions = append(f.tmpl.ExtraExtensions, pkix.Extension{Id: id, Critical: critical, Value: value})
	}
}

func mustMarshal(t testing.TB, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestIssueVerify(t *testing.T) {
	f := newFixture(t)
	der, issued, err := f.ca.Issue(&f.key.PublicKey, f.claims)
	if err != nil {
		t.Fatal(err)
	}
	f.der, f.keyID = der, issued.Serial
	got, err := f.verify()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Claims, f.claims) {
		t.Errorf("claims\n got %+v\nwant %+v", got.Claims, f.claims)
	}
	if len(got.Serial) != 32 || !got.Key.Equal(&f.key.PublicKey) {
		t.Errorf("serial %q, key %v", got.Serial, got.Key)
	}
	if !got.NotAfter.Equal(testNow.Add(Lifetime)) || !got.NotBefore.Equal(testNow.Add(-Backdate)) {
		t.Errorf("valid %v to %v", got.NotBefore, got.NotAfter)
	}
	if !got.HasRole("write") || got.HasRole("root") {
		t.Error("HasRole")
	}
	if p, ok := got.Passkey([]byte("phone")); !ok || !p.Key.Equal(f.claims.Passkeys[1].Key) {
		t.Error("Passkey")
	}
	if _, ok := got.Passkey([]byte("nope")); ok {
		t.Error("Passkey found an unknown ID")
	}
}

func TestMinimalClaims(t *testing.T) {
	f := newFixture(t)
	f.claims = Claims{User: "jack", Services: []string{testService}}
	der, issued, err := f.ca.Issue(&f.key.PublicKey, f.claims)
	if err != nil {
		t.Fatal(err)
	}
	f.der, f.keyID = der, issued.Serial
	f.r.RemoteAddr = "203.0.113.9:1" // no source restriction
	got, err := f.verify()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Claims, f.claims) || got.HasRole("write") {
		t.Errorf("claims %+v", got.Claims)
	}
}

func TestSourceAddresses(t *testing.T) {
	for addr, ok := range map[string]bool{
		"10.100.0.7:1":              true,
		"[::ffff:10.100.0.7]:1":     true, // IPv4-mapped
		"[fd00:100::5]:1":           true,
		"10.100.1.7:1":              false,
		"[fd00:101::5]:1":           false,
		"[fe80::1%wg0]:1":           false,
		"10.100.0.7":                false, // no port
		"farm-1:9200":               false,
		"":                          false,
		"[::ffff:10.100.1.7]:65535": false,
	} {
		f := newFixture(t)
		f.r.RemoteAddr = addr
		_, err := f.verify()
		if ok != (err == nil) || (err != nil && httpsig.ReasonOf(err) != httpsig.ReasonScope) {
			t.Errorf("%q: %v", addr, err)
		}
	}
	f := newFixture(t)
	f.v.Addr = func(*http.Request) (netip.Addr, error) { return netip.MustParseAddr("fd00:100::1"), nil }
	f.r.RemoteAddr = "203.0.113.9:1"
	if _, err := f.verify(); err != nil {
		t.Errorf("Addr func: %v", err)
	}
}

type mutation struct {
	name   string
	want   httpsig.Reason
	mutate func(*fixture)
}

var mutations = []mutation{
	// Encoding and chain.
	{"not DER", httpsig.ReasonCert, func(f *fixture) { f.der, f.keyID = []byte("not a certificate"), "00" }},
	{"trailing data", httpsig.ReasonCert, func(f *fixture) { f.build(); f.der = append(f.der, 0) }},
	{"other CA, same name", httpsig.ReasonCert, func(f *fixture) {
		other := newTestCA(f.t, "farm1 SSO CA")
		f.parent, f.signer = other.Cert, other.Key
	}},
	{"other CA", httpsig.ReasonCert, func(f *fixture) {
		other := newTestCA(f.t, "evil CA")
		f.parent, f.signer = other.Cert, other.Key
	}},
	{"self-signed", httpsig.ReasonCert, func(f *fixture) {
		f.tmpl.Subject = f.ca.Cert.Subject
		f.parent, f.signer = f.tmpl, f.key
	}},
	{"signature flipped", httpsig.ReasonCert, func(f *fixture) {
		f.build()
		f.der = bytes.Clone(f.der)
		f.der[len(f.der)-1] ^= 1
	}},
	{"keyid not the serial", httpsig.ReasonCert, func(f *fixture) { f.keyID = "40000000000000000000000000000000" }},
	{"keyid uppercase", httpsig.ReasonCert, func(f *fixture) {
		f.tmpl.SerialNumber, _ = new(big.Int).SetString("4abcdef0000000000000000000000000", 16)
		f.keyID = "4ABCDEF0000000000000000000000000"
	}},
	{"CA expired", httpsig.ReasonCert, func(f *fixture) {
		f.v.Now = func() time.Time { return f.ca.Cert.NotAfter.Add(time.Second) }
		f.tmpl.NotBefore, f.tmpl.NotAfter = f.ca.Cert.NotAfter, f.ca.Cert.NotAfter.Add(time.Hour)
	}},

	// Profile.
	{"P-384 client key", httpsig.ReasonCert, func(f *fixture) { f.pub = &newKey(f.t, elliptic.P384()).PublicKey }},
	{"ECDSA with SHA-384", httpsig.ReasonCert, func(f *fixture) { f.tmpl.SignatureAlgorithm = x509.ECDSAWithSHA384 }},
	{"serial too short", httpsig.ReasonCert, func(f *fixture) { f.tmpl.SerialNumber = big.NewInt(1) }},
	{"serial too long", httpsig.ReasonCert, func(f *fixture) {
		f.tmpl.SerialNumber = new(big.Int).Lsh(big.NewInt(1), 128)
	}},
	{"extra subject attribute", httpsig.ReasonCert, func(f *fixture) { f.tmpl.Subject.Organization = []string{"admin"} }},
	{"invalid user", httpsig.ReasonCert, func(f *fixture) { f.tmpl.Subject.CommonName = "Jack" }},
	{"empty user", httpsig.ReasonCert, func(f *fixture) { f.tmpl.Subject.CommonName = "" }},
	{"CA certificate", httpsig.ReasonCert, func(f *fixture) {
		f.tmpl.IsCA = true
		f.tmpl.KeyUsage |= x509.KeyUsageCertSign
	}},
	{"no basic constraints", httpsig.ReasonCert, func(f *fixture) { f.tmpl.BasicConstraintsValid = false }},
	{"extra key usage", httpsig.ReasonCert, func(f *fixture) { f.tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment }},
	{"server auth", httpsig.ReasonCert, func(f *fixture) {
		f.tmpl.ExtKeyUsage = append(f.tmpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}},
	{"unknown EKU", httpsig.ReasonCert, func(f *fixture) {
		f.tmpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3}}
	}},
	{"no EKU", httpsig.ReasonCert, func(f *fixture) { f.tmpl.ExtKeyUsage = nil }},
	{"lifetime too long", httpsig.ReasonCert, func(f *fixture) { f.tmpl.NotAfter = f.tmpl.NotAfter.Add(time.Second) }},
	{"not yet valid", httpsig.ReasonCert, func(f *fixture) {
		f.v.Now = func() time.Time { return f.tmpl.NotBefore.Add(-time.Second) }
	}},
	{"unknown extension", httpsig.ReasonCert, func(f *fixture) { f.setExt(asn1.ObjectIdentifier{1, 2, 3}, false, []byte{5, 0}) }},
	{"subject key ID", httpsig.ReasonCert, func(f *fixture) { f.tmpl.SubjectKeyId = []byte{1} }},
	{"no authority key ID", httpsig.ReasonCert, func(f *fixture) {
		parent := *f.ca.Cert
		parent.SubjectKeyId = nil
		f.parent = &parent
	}},

	// SAN.
	{"no SAN", httpsig.ReasonCert, func(f *fixture) { f.setExt(oidSAN, false, nil) }},
	{"DNS name in SAN", httpsig.ReasonCert, func(f *fixture) {
		f.setExt(oidSAN, false, mustMarshal(f.t, []asn1.RawValue{
			{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(ServicePrefix + testService)},
			{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("farm-1")},
		}))
	}},
	{"foreign URI in SAN", httpsig.ReasonCert, func(f *fixture) {
		f.setExt(oidSAN, false, mustMarshal(f.t, []asn1.RawValue{
			{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte("https://example.org/services/" + testService)},
		}))
	}},
	{"invalid service name", httpsig.ReasonCert, func(f *fixture) {
		f.setExt(oidSAN, false, mustMarshal(f.t, []asn1.RawValue{
			{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(ServicePrefix + testService + "/x")},
		}))
	}},
	{"repeated service", httpsig.ReasonCert, func(f *fixture) {
		v, _ := encodeServices([]string{testService, testService})
		f.setExt(oidSAN, false, v)
	}},
	{"empty SAN", httpsig.ReasonCert, func(f *fixture) { f.setExt(oidSAN, false, []byte{0x30, 0}) }},

	// Private extensions.
	{"roles critical", httpsig.ReasonCert, func(f *fixture) {
		v, _ := encodeRoles(f.claims.Roles)
		f.setExt(oidRoles, true, v)
	}},
	{"roles unsorted", httpsig.ReasonCert, func(f *fixture) { f.setExt(oidRoles, false, mustMarshal(f.t, []string{"write", "admin"})) }},
	{"roles repeated", httpsig.ReasonCert, func(f *fixture) { f.setExt(oidRoles, false, mustMarshal(f.t, []string{"write", "write"})) }},
	{"roles empty", httpsig.ReasonCert, func(f *fixture) { f.setExt(oidRoles, false, []byte{0x30, 0}) }},
	{"role as UTF8String", httpsig.ReasonCert, func(f *fixture) {
		f.setExt(oidRoles, false, mustMarshal(f.t, struct {
			R string `asn1:"utf8"`
		}{"write"}))
	}},
	{"passkeys critical", httpsig.ReasonCert, func(f *fixture) {
		v, _ := encodePasskeys(f.claims.Passkeys)
		f.setExt(oidPasskeys, true, v)
	}},
	{"passkey P-384", httpsig.ReasonCert, func(f *fixture) {
		spki, _ := x509.MarshalPKIXPublicKey(&newKey(f.t, elliptic.P384()).PublicKey)
		f.setExt(oidPasskeys, false, mustMarshal(f.t, []passkeyASN1{{ID: []byte("x"), Key: asn1.RawValue{FullBytes: spki}}}))
	}},
	{"passkey repeated ID", httpsig.ReasonCert, func(f *fixture) {
		pk := f.claims.Passkeys[0]
		v, _ := encodePasskeys([]Passkey{pk, {ID: pk.ID, Key: f.claims.Passkeys[1].Key}})
		f.setExt(oidPasskeys, false, v)
	}},
	{"passkey empty ID", httpsig.ReasonCert, func(f *fixture) {
		v, _ := encodePasskeys([]Passkey{{ID: []byte{}, Key: f.claims.Passkeys[0].Key}})
		f.setExt(oidPasskeys, false, v)
	}},
	{"sources not critical", httpsig.ReasonCert, func(f *fixture) {
		v, _ := encodeSources(f.claims.Sources)
		f.setExt(oidSources, false, v)
	}},
	{"source mask not contiguous", httpsig.ReasonCert, func(f *fixture) {
		f.setExt(oidSources, true, mustMarshal(f.t, [][]byte{{10, 0, 0, 0, 255, 0, 255, 0}}))
	}},
	{"source bits outside mask", httpsig.ReasonCert, func(f *fixture) {
		f.setExt(oidSources, true, mustMarshal(f.t, [][]byte{{10, 100, 0, 7, 255, 255, 255, 0}}))
	}},
	{"source IPv4-mapped", httpsig.ReasonCert, func(f *fixture) {
		v, _ := encodeSources([]netip.Prefix{netip.MustParsePrefix("::ffff:10.100.0.0/120")})
		f.setExt(oidSources, true, v)
	}},
	{"sources empty", httpsig.ReasonCert, func(f *fixture) { f.setExt(oidSources, true, []byte{0x30, 0}) }},

	// Expiry and scope, for certificates the CA really issued.
	{"expired", httpsig.ReasonCertExpired, func(f *fixture) {
		f.v.Now = func() time.Time { return f.tmpl.NotAfter.Add(time.Second) }
	}},
	{"other service", httpsig.ReasonScope, func(f *fixture) { f.v.service = "billing" }},
	{"source address outside", httpsig.ReasonScope, func(f *fixture) { f.r.RemoteAddr = "10.100.1.7:51000" }},
	{"Addr fails", httpsig.ReasonScope, func(f *fixture) {
		f.v.Addr = func(*http.Request) (netip.Addr, error) { return netip.Addr{}, errors.New("no address") }
	}},
}

func TestMutations(t *testing.T) {
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			f := newFixture(t)
			m.mutate(f)
			_, err := f.verify()
			var e *httpsig.Error
			if !errors.As(err, &e) || e.Reason != m.want {
				t.Fatalf("got %v, want %s", err, m.want)
			}
			t.Log(e)
		})
	}
}

// TestEveryReasonCovered checks each reason a Cert func may return has a
// mutation.
func TestEveryReasonCovered(t *testing.T) {
	for _, r := range []httpsig.Reason{httpsig.ReasonCert, httpsig.ReasonCertExpired, httpsig.ReasonScope} {
		if !slices.ContainsFunc(mutations, func(m mutation) bool { return m.want == r }) {
			t.Errorf("no mutation for %s", r)
		}
	}
}

// TestFixtureVerifies checks the unmutated fixture passes, so each mutation
// is what makes its case fail.
func TestFixtureVerifies(t *testing.T) {
	if _, err := newFixture(t).verify(); err != nil {
		t.Fatal(err)
	}
}

func TestIssueRejects(t *testing.T) {
	f := newFixture(t)
	for name, mutate := range map[string]func(*Claims){
		"invalid user":       func(c *Claims) { c.User = "jack@farm" },
		"no services":        func(c *Claims) { c.Services = nil },
		"repeated service":   func(c *Claims) { c.Services = []string{"a", "a"} },
		"invalid service":    func(c *Claims) { c.Services = []string{"A"} },
		"roles unsorted":     func(c *Claims) { c.Roles = []string{"write", "admin"} },
		"roles empty":        func(c *Claims) { c.Roles = []string{} },
		"passkeys empty":     func(c *Claims) { c.Passkeys = []Passkey{} },
		"passkey nil key":    func(c *Claims) { c.Passkeys = []Passkey{{ID: []byte("x")}} },
		"passkey ID too big": func(c *Claims) { c.Passkeys[0].ID = make([]byte, maxCredentialID+1) },
		"sources empty":      func(c *Claims) { c.Sources = []netip.Prefix{} },
		"source unmasked":    func(c *Claims) { c.Sources = []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr("10.0.0.1"), 8)} },
		"source zero value":  func(c *Claims) { c.Sources = []netip.Prefix{{}} },
	} {
		c := testClaims(t)
		mutate(&c)
		if _, _, err := f.ca.Issue(&f.key.PublicKey, c); err == nil {
			t.Errorf("%s: issued", name)
		}
	}
	if _, _, err := f.ca.Issue(&newKey(t, elliptic.P384()).PublicKey, f.claims); err == nil {
		t.Error("P-384 client key: issued")
	}
}

func TestCASetup(t *testing.T) {
	ca := newTestCA(t, "farm1 SSO CA")
	if _, err := NewCAFromDER(ca.Cert.Raw, newKey(t, elliptic.P256())); err == nil {
		t.Error("NewCAFromDER accepted a key that doesn't match")
	}
	if _, err := NewCA("x", newKey(t, elliptic.P384()), testNow, testNow.Add(time.Hour)); err == nil {
		t.Error("NewCA accepted a P-384 key")
	}
	if _, err := NewVerifier(ca.Cert.Raw, "Statusd"); err == nil {
		t.Error("NewVerifier accepted an invalid service name")
	}
	f := newFixture(t)
	f.build()
	if _, err := NewVerifier(f.der, testService); err == nil {
		t.Error("NewVerifier accepted a client certificate as the CA")
	}
	if _, err := NewVerifier([]byte("x"), testService); err == nil {
		t.Error("NewVerifier accepted garbage")
	}
}

// TestWithHTTPSig signs a request with an issued certificate and verifies it
// with an httpsig.Verifier whose Cert func is a cert.Verifier.
func TestWithHTTPSig(t *testing.T) {
	f := newFixture(t)
	der, issued, err := f.ca.Issue(&f.key.PublicKey, f.claims)
	if err != nil {
		t.Fatal(err)
	}
	signer := &httpsig.Signer{Key: f.key, Cert: der, KeyID: issued.Serial, Now: func() time.Time { return testNow }}
	hv := &httpsig.Verifier[*Cert]{
		Authorities: []string{"farm-1:9200"},
		Cert:        f.v.Verify,
		Nonces:      httpsig.NewNonceCache(8),
		Started:     testNow.Add(-time.Hour),
		Now:         func() time.Time { return testNow },
	}
	request := func() *http.Request {
		body := []byte(`{"vm":"web"}`)
		r := httptest.NewRequest(http.MethodPost, "http://farm-1:9200/v1/microvms/web/restart", bytes.NewReader(body))
		r.RemoteAddr = testRemote
		if _, err := signer.Sign(r, body); err != nil {
			t.Fatal(err)
		}
		return r
	}

	got, err := hv.Verify(request(), []byte(`{"vm":"web"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.Cert.User != "jack" || !got.Cert.HasRole("write") || got.Params.KeyID != issued.Serial {
		t.Errorf("verified %+v", got)
	}

	// A different key with the same certificate fails at the signature.
	signer.Key = newKey(t, elliptic.P256())
	if _, err := hv.Verify(request(), []byte(`{"vm":"web"}`)); httpsig.ReasonOf(err) != httpsig.ReasonSigMismatch {
		t.Errorf("other key: %v", err)
	}
	// A source address outside the certificate's prefixes is a scope failure
	// through httpsig too.
	signer.Key = f.key
	r := request()
	r.RemoteAddr = "192.0.2.1:1"
	if _, err := hv.Verify(r, []byte(`{"vm":"web"}`)); httpsig.ReasonOf(err) != httpsig.ReasonScope {
		t.Errorf("source: %v", err)
	}
}
