package assertion

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oxgen1/sso/lib/cert"
	"github.com/oxgen1/sso/lib/httpsig"
)

const (
	testRPID   = "auth.jack.farm"
	testOrigin = "https://id.auth.jack.farm"
)

var (
	testNow  = time.Unix(1_800_000_000, 0)
	testBase = []byte(`"@method": DELETE` + "\n" + `"@signature-params": ("@method");nonce="n"`)
)

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newVerifier(t testing.TB) *Verifier {
	t.Helper()
	v, err := NewVerifier(testRPID, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// response is what the authenticator and the browser put together, kept in
// parts so a test can change any of them before it's signed.
type response struct {
	credID    []byte
	key       *ecdsa.PrivateKey
	rpID      string
	flags     byte
	counter   uint32
	adTail    []byte // after signCount
	typ       string
	challenge []byte
	origin    string
	cdTail    string // after the origin's closing quote
	cdRaw     string // replaces the whole clientDataJSON when set
	post      func(*Assertion)
}

// authenticator is a software passkey: the response it gives for base by
// default is what a browser on the approval page sends back.
type authenticator struct {
	id  []byte
	key *ecdsa.PrivateKey
}

func newAuthenticator(t testing.TB) authenticator {
	id := make([]byte, 16)
	rand.Read(id)
	return authenticator{id: id, key: newKey(t)}
}

func (a authenticator) response(base []byte) response {
	return response{
		credID:    a.id,
		key:       a.key,
		rpID:      testRPID,
		flags:     flagUP | flagUV,
		typ:       "webauthn.get",
		challenge: Challenge(base),
		origin:    testOrigin,
		cdTail:    `,"crossOrigin":false}`,
	}
}

func (r response) sign(t testing.TB) *Assertion {
	t.Helper()
	rp := sha256.Sum256([]byte(r.rpID))
	ad := append(rp[:], r.flags, byte(r.counter>>24), byte(r.counter>>16), byte(r.counter>>8), byte(r.counter))
	ad = append(ad, r.adTail...)
	cd := r.cdRaw
	if cd == "" {
		cd = fmt.Sprintf(`{"type":%q,"challenge":%q,"origin":%q%s`,
			r.typ, base64.RawURLEncoding.EncodeToString(r.challenge), r.origin, r.cdTail)
	}
	h := sha256.Sum256([]byte(cd))
	signed := sha256.Sum256(append(slices.Clip(ad), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, r.key, signed[:])
	if err != nil {
		t.Fatal(err)
	}
	a := &Assertion{CredentialID: r.credID, AuthenticatorData: ad, ClientDataJSON: []byte(cd), Signature: sig}
	if r.post != nil {
		r.post(a)
	}
	return a
}

// certFor is a parsed certificate holding these passkeys, as cert.Verifier
// would hand it over.
func certFor(auths ...authenticator) *cert.Cert {
	c := &cert.Cert{Serial: "4f0c0e8d2b6a41c79e5d3a2f1b0c9d8e"}
	c.User = "jack"
	for _, a := range auths {
		c.Passkeys = append(c.Passkeys, cert.Passkey{ID: a.id, Key: &a.key.PublicKey})
	}
	return c
}

type mutation struct {
	name   string
	change func(*response)
	want   Reason // "" means accepted
}

func mutations(t testing.TB) []mutation {
	other := newAuthenticator(t)
	return []mutation{
		{"valid", func(*response) {}, ""},

		// Accepted variations real authenticators and browsers produce.
		{"no crossOrigin", func(r *response) { r.cdTail = "}" }, ""},
		{"extra keys", func(r *response) {
			r.cdTail = `,"crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}`
		}, ""},
		{"backup flags", func(r *response) { r.flags |= 1<<3 | 1<<4 }, ""},
		{"reserved flags", func(r *response) { r.flags |= 1<<1 | 1<<5 }, ""},
		{"counter", func(r *response) { r.counter = 41 }, ""},
		{"counter max", func(r *response) { r.counter = 1<<32 - 1 }, ""},

		{"short authenticatorData", func(r *response) {
			r.post = func(a *Assertion) { a.AuthenticatorData = a.AuthenticatorData[:authDataLen-1] }
		}, ReasonMalformed},
		{"trailing authenticatorData", func(r *response) { r.adTail = []byte{0} }, ReasonMalformed},
		{"clientData not starting with type", func(r *response) {
			r.cdRaw = `{"challenge":"x","type":"webauthn.get"}`
		}, ReasonMalformed},
		{"clientData space after brace", func(r *response) {
			r.cdRaw = `{ "type":"webauthn.get"}`
		}, ReasonMalformed},
		{"clientData invalid JSON tail", func(r *response) { r.cdTail = `,}` }, ReasonMalformed},
		{"clientData unterminated", func(r *response) { r.cdTail = `,"crossOrigin":false` }, ReasonMalformed},
		{"clientData crossOrigin not bool", func(r *response) { r.cdTail = `,"crossOrigin":"false"}` }, ReasonMalformed},

		{"unknown credential", func(r *response) { r.credID = other.id }, ReasonCredential},
		{"credential ID prefix", func(r *response) { r.credID = r.credID[:15] }, ReasonCredential},

		{"other key", func(r *response) { r.key = other.key }, ReasonSigMismatch},
		{"clientData changed after signing", func(r *response) {
			r.post = func(a *Assertion) {
				a.ClientDataJSON = bytes.Replace(a.ClientDataJSON, []byte("false"), []byte("true "), 1)
			}
		}, ReasonSigMismatch},
		{"authenticatorData changed after signing", func(r *response) {
			r.post = func(a *Assertion) { a.AuthenticatorData[32] ^= 1 << 3 }
		}, ReasonSigMismatch},
		{"signature truncated", func(r *response) {
			r.post = func(a *Assertion) { a.Signature = a.Signature[:len(a.Signature)-1] }
		}, ReasonSigMismatch},
		{"signature raw r||s", func(r *response) {
			r.post = func(a *Assertion) { a.Signature = make([]byte, 64) }
		}, ReasonSigMismatch},

		{"parent RP ID", func(r *response) { r.rpID = "jack.farm" }, ReasonRP},
		{"origin host as RP ID", func(r *response) { r.rpID = "id.auth.jack.farm" }, ReasonRP},

		{"no flags", func(r *response) { r.flags = 0 }, ReasonFlags},
		{"UP only", func(r *response) { r.flags = flagUP }, ReasonFlags},
		{"UV only", func(r *response) { r.flags = flagUV }, ReasonFlags},
		{"attested credential data", func(r *response) { r.flags |= flagAT }, ReasonFlags},
		{"extensions", func(r *response) { r.flags |= flagED; r.adTail = []byte{0xa0} }, ReasonFlags},

		{"create", func(r *response) { r.typ = "webauthn.create" }, ReasonType},
		{"payment", func(r *response) { r.typ = "payment.get" }, ReasonType},
		{"type with prefix", func(r *response) { r.typ = "webauthn.getx" }, ReasonType},

		{"other request", func(r *response) { r.challenge = Challenge([]byte("other base")) }, ReasonChallenge},
		{"base itself", func(r *response) { r.challenge = testBase }, ReasonChallenge},
		{"empty challenge", func(r *response) { r.challenge = nil }, ReasonChallenge},
		{"padded challenge", func(r *response) {
			r.cdRaw = fmt.Sprintf(`{"type":"webauthn.get","challenge":%q,"origin":%q}`,
				base64.URLEncoding.EncodeToString(r.challenge), testOrigin)
		}, ReasonChallenge},
		{"standard base64 challenge", func(r *response) {
			r.cdRaw = fmt.Sprintf(`{"type":"webauthn.get","challenge":%q,"origin":%q}`,
				base64.StdEncoding.EncodeToString(r.challenge), testOrigin)
		}, ReasonChallenge},
		{"origin before challenge", func(r *response) {
			r.cdRaw = fmt.Sprintf(`{"type":"webauthn.get","origin":%q,"challenge":%q}`,
				testOrigin, base64.RawURLEncoding.EncodeToString(r.challenge))
		}, ReasonChallenge},

		{"sibling origin", func(r *response) { r.origin = "https://grafana.auth.jack.farm" }, ReasonOrigin},
		{"parent origin", func(r *response) { r.origin = "https://auth.jack.farm" }, ReasonOrigin},
		{"origin with port", func(r *response) { r.origin = testOrigin + ":443" }, ReasonOrigin},
		{"origin with path", func(r *response) { r.origin = testOrigin + "/" }, ReasonOrigin},
		{"origin suffix", func(r *response) { r.origin = testOrigin + ".evil.example" }, ReasonOrigin},
		{"http origin", func(r *response) { r.origin = "http://id.auth.jack.farm" }, ReasonOrigin},
		{"uppercase origin", func(r *response) { r.origin = "https://ID.auth.jack.farm" }, ReasonOrigin},
		{"cross-origin iframe", func(r *response) { r.cdTail = `,"crossOrigin":true}` }, ReasonOrigin},
		{"top origin", func(r *response) {
			r.cdTail = `,"crossOrigin":false,"topOrigin":"https://evil.example"}`
		}, ReasonOrigin},
		{"crossOrigin repeated", func(r *response) {
			r.cdTail = `,"crossOrigin":false,"crossOrigin":true}`
		}, ReasonOrigin},
		{"origin then garbage", func(r *response) { r.cdTail = `x}` }, ReasonOrigin},
		{"origin then nothing", func(r *response) { r.cdTail = `` }, ReasonOrigin},
	}
}

func TestMutations(t *testing.T) {
	v := newVerifier(t)
	auth := newAuthenticator(t)
	c := certFor(newAuthenticator(t), auth)
	for _, m := range mutations(t) {
		t.Run(m.name, func(t *testing.T) {
			r := auth.response(testBase)
			m.change(&r)
			err := v.Check(r.sign(t), testBase, c)
			if got := ReasonOf(err); got != m.want {
				t.Errorf("reason %q, want %q (%v)", got, m.want, err)
			}
			if err != nil && ReasonOf(err) == "" {
				t.Errorf("error without a reason: %v", err)
			}
		})
	}
}

// TestEveryReasonCovered fails if a reason has no test that produces it.
func TestEveryReasonCovered(t *testing.T) {
	seen := map[Reason]bool{ReasonMissing: true} // TestVerifyHeader
	for _, m := range mutations(t) {
		seen[m.want] = true
	}
	for _, r := range Reasons() {
		if !seen[r] {
			t.Errorf("no test produces %s", r)
		}
	}
}

func TestVerifyHeader(t *testing.T) {
	v := newVerifier(t)
	auth := newAuthenticator(t)
	got := &httpsig.Verified[*cert.Cert]{Base: testBase, Cert: certFor(auth)}
	value := auth.response(testBase).sign(t).Value()

	for _, tc := range []struct {
		name   string
		values []string
		want   Reason
	}{
		{"valid", []string{value}, ""},
		{"missing", nil, ReasonMissing},
		{"twice", []string{value, value}, ReasonMalformed},
		{"unparsable", []string{"id=:AA==:"}, ReasonMalformed},
	} {
		r := httptest.NewRequest(http.MethodDelete, "http://farm-1:9021/v1/microvms/old", nil)
		for _, val := range tc.values {
			r.Header.Add(Header, val)
		}
		if err := v.Verify(r, got); ReasonOf(err) != tc.want {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	a := &Assertion{CredentialID: []byte{1, 2, 3}, AuthenticatorData: []byte{4}, ClientDataJSON: []byte("{}"), Signature: []byte{5, 6}}
	want := "id=:AQID:, ad=:BA==:, cd=:e30=:, sig=:BQY=:"
	if got := a.Value(); got != want {
		t.Fatalf("Value() = %q, want %q", got, want)
	}
	b, err := Parse(want)
	if err != nil {
		t.Fatal(err)
	}
	if b.Value() != want {
		t.Errorf("round trip %q", b.Value())
	}
}

func TestParseRejects(t *testing.T) {
	long := base64.StdEncoding.EncodeToString(make([]byte, maxCredentialID+1))
	for _, s := range []string{
		"",
		"id=:AQID:, ad=:BA==:, cd=:e30=:", // member missing
		"id=:AQID:, ad=:BA==:, cd=:e30=:, sig=:BQY=:, x=:AA==:",                         // extra member
		"ad=:BA==:, id=:AQID:, cd=:e30=:, sig=:BQY=:",                                   // order
		"id=:AQID:,ad=:BA==:, cd=:e30=:, sig=:BQY=:",                                    // no space
		"id=:AQID:,  ad=:BA==:, cd=:e30=:, sig=:BQY=:",                                  // two spaces
		"id=:AQID:, ad=:BA:, cd=:e30=:, sig=:BQY=:",                                     // unpadded
		"id=:AQID:, ad=:BA==:, cd=:e3-=:, sig=:BQY=:",                                   // base64url
		"id=:AQID:, ad=:BA==:, cd=:e30=:, sig=:BQZ=:",                                   // non-zero padding bits
		"id=:AQ\r\nID:, ad=:BA==:, cd=:e30=:, sig=:BQY=:",                               // CRLF skipped by Go's decoder
		"id=::, ad=:BA==:, cd=:e30=:, sig=:BQY=:",                                       // empty
		"id=AQID, ad=:BA==:, cd=:e30=:, sig=:BQY=:",                                     // not a byte sequence
		"id=:AQID:;x, ad=:BA==:, cd=:e30=:, sig=:BQY=:",                                 // parameter
		"id=:" + long + ":, ad=:BA==:, cd=:e30=:, sig=:BQY=:",                           // credential ID too long
		"id=:AQID:, ad=:BA==:, cd=:" + strings.Repeat("A", maxHeader) + ":, sig=:BQY=:", // too long
	} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%.60q) succeeded", s)
		}
	}
}

func TestNewVerifier(t *testing.T) {
	for _, tc := range []struct {
		rpID, origin string
		ok           bool
	}{
		{"auth.jack.farm", "https://id.auth.jack.farm", true},
		{"auth.jack.farm", "https://auth.jack.farm", true},
		{"auth.jack.farm", "https://a.b.auth.jack.farm", true},
		{"auth.jack.farm", "https://jack.farm", false},
		{"auth.jack.farm", "https://idauth.jack.farm", false},
		{"auth.jack.farm", "http://id.auth.jack.farm", false},
		{"auth.jack.farm", "https://id.auth.jack.farm:8443", false},
		{"auth.jack.farm", "https://id.auth.jack.farm/", false},
		{"auth.jack.farm", "https://ID.auth.jack.farm", false},
		{"auth.jack.farm", `https://id"x.auth.jack.farm`, false},
		{"Auth.jack.farm", "https://id.auth.jack.farm", false},
		{"auth..jack.farm", "https://id.auth..jack.farm", false},
		{"", "https://", false},
		{"-auth.jack.farm", "https://id.-auth.jack.farm", false},
	} {
		_, err := NewVerifier(tc.rpID, tc.origin)
		if (err == nil) != tc.ok {
			t.Errorf("NewVerifier(%q, %q): %v", tc.rpID, tc.origin, err)
		}
	}
}

// TestWithHTTPSig runs the whole destructive tier: issue a certificate with a
// passkey, sign a request, verify it with httpsig and cert, approve its base
// with the passkey, and check the assertion.
func TestWithHTTPSig(t *testing.T) {
	caKey := newKey(t)
	caDER, err := cert.NewCA("farm1 SSO CA", caKey, testNow.Add(-time.Hour), testNow.Add(time.Hour*24))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := cert.NewCAFromDER(caDER, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca.Now = func() time.Time { return testNow }
	auth := newAuthenticator(t)
	clientKey := newKey(t)
	der, issued, err := ca.Issue(&clientKey.PublicKey, cert.Claims{
		User:     "jack",
		Services: []string{"statusd"},
		Roles:    []string{"admin"},
		Passkeys: []cert.Passkey{{ID: auth.id, Key: &auth.key.PublicKey}},
	})
	if err != nil {
		t.Fatal(err)
	}
	certs, err := cert.NewVerifier(caDER, "statusd")
	if err != nil {
		t.Fatal(err)
	}
	certs.Now = func() time.Time { return testNow }
	hv := &httpsig.Verifier[*cert.Cert]{
		Authorities: []string{"farm-1.wg:9021"},
		Cert:        certs.Verify,
		Nonces:      httpsig.NewNonceCache(8),
		Started:     testNow.Add(-time.Hour),
		Now:         func() time.Time { return testNow },
	}
	signer := &httpsig.Signer{Key: clientKey, Cert: der, KeyID: issued.Serial, Now: func() time.Time { return testNow }}
	v := newVerifier(t)

	request := func() (*http.Request, []byte) {
		r := httptest.NewRequest(http.MethodDelete, "http://farm-1.wg:9021/v1/microvms/old", nil)
		r.RemoteAddr = "10.100.0.10:50000"
		base, err := signer.Sign(r, nil)
		if err != nil {
			t.Fatal(err)
		}
		return r, base
	}

	// mvm signs, the approval page signs the base's hash, mvm adds the header.
	r, base := request()
	r.Header.Set(Header, auth.response(base).sign(t).Value())
	got, err := hv.Verify(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Base, base) {
		t.Fatalf("verifier's base differs from the signer's:\n%s\n%s", got.Base, base)
	}
	if err := v.Verify(r, got); err != nil {
		t.Fatal(err)
	}

	// The same approval on a re-signed request (new nonce) is for a different
	// request.
	approved := r.Header.Get(Header)
	r2, _ := request()
	r2.Header.Set(Header, approved)
	got2, err := hv.Verify(r2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(r2, got2); ReasonOf(err) != ReasonChallenge {
		t.Errorf("approval reused on another request: %v", err)
	}
}

// TestCheckChallenge is sign-in: a random challenge and the passkeys from the
// IdP's configuration, with no certificate.
func TestCheckChallenge(t *testing.T) {
	v := newVerifier(t)
	auth, other := newAuthenticator(t), newAuthenticator(t)
	challenge := make([]byte, 32)
	rand.Read(challenge)
	r := auth.response(nil)
	r.challenge = challenge
	a := r.sign(t)
	keys := certFor(other, auth).Passkeys
	if err := v.CheckChallenge(a, challenge, keys); err != nil {
		t.Fatal(err)
	}
	if err := v.CheckChallenge(a, challenge, keys[:1]); ReasonOf(err) != ReasonCredential {
		t.Errorf("other user's passkeys: %v", err)
	}
	if err := v.CheckChallenge(a, Challenge(challenge), keys); ReasonOf(err) != ReasonChallenge {
		t.Errorf("wrong challenge: %v", err)
	}
}

// TestCheckClientDataCreate is registration, which has no assertion around
// the client data.
func TestCheckClientDataCreate(t *testing.T) {
	v := newVerifier(t)
	challenge := []byte{1, 2, 3}
	cd := func(typ string) []byte {
		return []byte(`{"type":"` + typ + `","challenge":"AQID","origin":"` + testOrigin + `","crossOrigin":false}`)
	}
	if err := v.CheckClientData(cd("webauthn.create"), "webauthn.create", challenge); err != nil {
		t.Error(err)
	}
	if err := v.CheckClientData(cd("webauthn.get"), "webauthn.create", challenge); ReasonOf(err) != ReasonType {
		t.Errorf("get as create: %v", err)
	}
	if err := v.CheckClientData(cd("webauthn.create"), "webauthn.get", challenge); ReasonOf(err) != ReasonType {
		t.Errorf("create as get: %v", err)
	}
}
