package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/oxgen1/sso/lib/cert"
)

var testNow = time.Unix(1_800_000_000, 0)

const caPath = "/nix/store/x-ca.pem"

type fixture struct {
	caKey     *ecdsa.PrivateKey
	caPEM     []byte
	passkeys  []*ecdsa.PrivateKey
	otherCurv *ecdsa.PrivateKey
}

func newKey(t testing.TB, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	fx := &fixture{caKey: newKey(t, elliptic.P256())}
	der, err := cert.NewCA("test CA", fx.caKey, testNow, testNow.Add(365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	fx.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for range 3 {
		fx.passkeys = append(fx.passkeys, newKey(t, elliptic.P256()))
	}
	fx.otherCurv = newKey(t, elliptic.P384())
	return fx
}

func spki(t testing.TB, k *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// valid is example 2 from docs/setup.md.
func (fx *fixture) valid(t testing.TB) file {
	var f file
	f.RPID = "auth.jack.farm"
	f.Origin = "https://id.auth.jack.farm"
	f.ListenAddress = "127.0.0.1:9300"
	f.CACertificate = caPath
	f.Users = map[string]fileUser{
		"jack": {
			Roles:    []string{"write", "admin"},
			Services: []string{"statusd", "grafana"},
			Sources:  []string{"10.100.0.0/24", "10.0.0.0/24"},
			Passkeys: []filePasskey{
				{Name: "yubikey-5c", ID: "a08v", PublicKey: spki(t, fx.passkeys[0])},
				{Name: "pixel", ID: "Zt8q-w", PublicKey: spki(t, fx.passkeys[1])},
			},
		},
		"guest": {
			Roles:    []string{},
			Services: []string{"grafana"},
			Sources:  []string{"10.0.0.0/24"},
			Passkeys: []filePasskey{{Name: "iphone", ID: "c2Vj", PublicKey: spki(t, fx.passkeys[2])}},
		},
		// Not enrolled yet: sso enroll needs the user to exist.
		"new": {Services: []string{"statusd"}, Passkeys: []filePasskey{}},
	}
	f.Clients = map[string]fileClient{"grafana": {RedirectURI: "https://grafana.jack.farm/.sso/callback"}}
	f.Audit.RetentionDays = 90
	return f
}

func (fx *fixture) parse(t testing.TB, f file) (*Config, error) {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return fx.parseBytes(b)
}

func (fx *fixture) parseBytes(b []byte) (*Config, error) {
	return parse(bytes.NewReader(b), func(path string) ([]byte, error) {
		if path != caPath {
			return nil, os.ErrNotExist
		}
		return fx.caPEM, nil
	})
}

func TestValid(t *testing.T) {
	fx := newFixture(t)
	c, err := fx.parse(t, fx.valid(t))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != netip.MustParseAddrPort("127.0.0.1:9300") || c.RetentionDays != 90 {
		t.Errorf("listen %v, retention %d", c.Listen, c.RetentionDays)
	}
	jack := c.Users["jack"].Claims
	want := cert.Claims{
		User:     "jack",
		Services: []string{"statusd", "grafana"},
		Roles:    []string{"admin", "write"},
		Sources:  []netip.Prefix{netip.MustParsePrefix("10.100.0.0/24"), netip.MustParsePrefix("10.0.0.0/24")},
		Passkeys: []cert.Passkey{
			{ID: []byte{0x6b, 0x4f, 0x2f}, Key: &fx.passkeys[0].PublicKey},
			{ID: []byte{0x66, 0xdf, 0x2a, 0xfb}, Key: &fx.passkeys[1].PublicKey},
		},
	}
	if !reflect.DeepEqual(jack, want) {
		t.Errorf("jack's claims:\n got %+v\nwant %+v", jack, want)
	}
	// Empty lists leave the extension out of the certificate.
	if guest := c.Users["guest"].Claims; guest.Roles != nil {
		t.Errorf("guest roles %#v, want nil", guest.Roles)
	}
	if n := c.Users["new"]; n.Claims.Passkeys != nil || n.Claims.Sources != nil {
		t.Errorf("new: %+v", n.Claims)
	}
	if c.Clients["grafana"].RedirectURI != "https://grafana.jack.farm/.sso/callback" {
		t.Errorf("clients %+v", c.Clients)
	}

	// Every user's claims are fit to issue.
	ca, err := c.parseCA(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8(t, fx.caKey)}))
	if err != nil {
		t.Fatal(err)
	}
	ca.Now = func() time.Time { return testNow }
	for name, u := range c.Users {
		if _, _, err := ca.Issue(&fx.passkeys[0].PublicKey, u.Claims); err != nil {
			t.Errorf("issue for %s: %v", name, err)
		}
	}
}

func pkcs8(t testing.TB, k any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestPasskeyOwner(t *testing.T) {
	fx := newFixture(t)
	c, err := fx.parse(t, fx.valid(t))
	if err != nil {
		t.Fatal(err)
	}
	u, p, ok := c.PasskeyOwner([]byte{0x66, 0xdf, 0x2a, 0xfb})
	if !ok || u.Claims.User != "jack" || p.Name != "pixel" || !p.Key.Equal(&fx.passkeys[1].PublicKey) {
		t.Errorf("PasskeyOwner(pixel) = %v, %+v, %v", u, p, ok)
	}
	if _, _, ok := c.PasskeyOwner([]byte("nope")); ok {
		t.Error("unknown credential ID found")
	}
}

func TestRejects(t *testing.T) {
	fx := newFixture(t)
	jack := func(f *file, change func(*fileUser)) {
		u := f.Users["jack"]
		u.Passkeys = append([]filePasskey(nil), u.Passkeys...)
		change(&u)
		f.Users["jack"] = u
	}
	cases := []struct {
		name   string
		change func(*file)
		want   string
	}{
		{"RP ID uppercase", func(f *file) { f.RPID = "Auth.jack.farm" }, "RP ID"},
		{"origin http", func(f *file) { f.Origin = "http://id.auth.jack.farm" }, "origin"},
		{"origin off RP ID", func(f *file) { f.Origin = "https://id.jack.farm" }, "isn't on RP ID"},
		{"origin with port", func(f *file) { f.Origin = "https://id.auth.jack.farm:8443" }, "origin"},
		{"listen host name", func(f *file) { f.ListenAddress = "localhost:9300" }, "listenAddress"},
		{"listen empty", func(f *file) { f.ListenAddress = "" }, "listenAddress"},
		{"no retention", func(f *file) { f.Audit.RetentionDays = 0 }, "retentionDays"},
		{"CA missing", func(f *file) { f.CACertificate = "/elsewhere" }, "caCertificate"},
		{"no users", func(f *file) { f.Users = nil }, "no users"},
		{"user name", func(f *file) { f.Users["Jack"] = f.Users["jack"]; delete(f.Users, "jack") }, "users.Jack"},
		{"no services", func(f *file) { jack(f, func(u *fileUser) { u.Services = nil }) }, "no services"},
		{"service repeated", func(f *file) { jack(f, func(u *fileUser) { u.Services = []string{"a", "a"} }) }, "repeated"},
		{"role repeated", func(f *file) { jack(f, func(u *fileUser) { u.Roles = []string{"write", "write"} }) }, "roles"},
		{"role name", func(f *file) { jack(f, func(u *fileUser) { u.Roles = []string{"Write"} }) }, "role"},
		{"source host bits", func(f *file) { jack(f, func(u *fileUser) { u.Sources = []string{"10.0.0.1/24"} }) }, "did you mean 10.0.0.0/24"},
		{"source bare address", func(f *file) { jack(f, func(u *fileUser) { u.Sources = []string{"10.0.0.1"} }) }, "sources"},
		{"source zone", func(f *file) { jack(f, func(u *fileUser) { u.Sources = []string{"fe80::%eth0/64"} }) }, "sources"},
		{"passkey name", func(f *file) { jack(f, func(u *fileUser) { u.Passkeys[0].Name = "YubiKey 5C" }) }, "passkeys[0]: name"},
		{"passkey name repeated", func(f *file) { jack(f, func(u *fileUser) { u.Passkeys[1].Name = u.Passkeys[0].Name }) }, "passkeys[1]: name"},
		{"passkey ID padded", func(f *file) { jack(f, func(u *fileUser) { u.Passkeys[0].ID = "a08=" }) }, "passkeys[0]: id"},
		{"passkey ID std base64", func(f *file) { jack(f, func(u *fileUser) { u.Passkeys[1].ID = "Zt8q+w" }) }, "passkeys[1]: id"},
		{"passkey ID empty", func(f *file) { jack(f, func(u *fileUser) { u.Passkeys[0].ID = "" }) }, "credential ID length"},
		{"passkey ID too long", func(f *file) {
			jack(f, func(u *fileUser) { u.Passkeys[0].ID = base64.RawURLEncoding.EncodeToString(make([]byte, 1024)) })
		}, "credential ID length"},
		{"passkey ID repeated", func(f *file) { jack(f, func(u *fileUser) { u.Passkeys[1].ID = u.Passkeys[0].ID }) }, "credential ID already enrolled for jack"},
		{"passkey ID other user", func(f *file) { jack(f, func(u *fileUser) { u.Passkeys[0].ID = "c2Vj" }) }, "already enrolled for guest"},
		{"public key P-384", func(f *file) { jack(f, func(u *fileUser) { u.Passkeys[0].PublicKey = spki(t, fx.otherCurv) }) }, "P-256"},
		{"public key garbage", func(f *file) { jack(f, func(u *fileUser) { u.Passkeys[0].PublicKey = "AAAA" }) }, "publicKey"},
		{"public key unpadded", func(f *file) {
			jack(f, func(u *fileUser) { u.Passkeys[0].PublicKey = strings.TrimRight(u.Passkeys[0].PublicKey, "=") })
		}, "publicKey"},
		{"client name", func(f *file) { f.Clients["Grafana"] = f.Clients["grafana"] }, "clients.Grafana"},
		{"redirect http", func(f *file) { f.Clients["grafana"] = fileClient{"http://grafana.jack.farm/cb"} }, "redirectUri"},
		{"redirect query", func(f *file) { f.Clients["grafana"] = fileClient{"https://grafana.jack.farm/cb?x=1"} }, "redirectUri"},
		{"redirect empty query", func(f *file) { f.Clients["grafana"] = fileClient{"https://grafana.jack.farm/cb?"} }, "redirectUri"},
		{"redirect fragment", func(f *file) { f.Clients["grafana"] = fileClient{"https://grafana.jack.farm/cb#x"} }, "redirectUri"},
		{"redirect user", func(f *file) { f.Clients["grafana"] = fileClient{"https://a@grafana.jack.farm/cb"} }, "redirectUri"},
		{"redirect no host", func(f *file) { f.Clients["grafana"] = fileClient{"https:///cb"} }, "redirectUri"},
		{"redirect scheme case", func(f *file) { f.Clients["grafana"] = fileClient{"HTTPS://grafana.jack.farm/cb"} }, "redirectUri"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := fx.valid(t)
			tc.change(&f)
			_, err := fx.parse(t, f)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestRejectsJSON(t *testing.T) {
	fx := newFixture(t)
	b, err := json.Marshal(fx.valid(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string][]byte{
		"unknown field": append([]byte(`{"users2":{},`), b[1:]...),
		"trailing data": append(bytes.Clone(b), `{}`...),
		"truncated":     b[:len(b)-1],
		"not an object": []byte(`[]`),
	} {
		if _, err := fx.parseBytes(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := fx.parseBytes(append(bytes.Clone(b), " \n"...)); err != nil {
		t.Errorf("trailing whitespace: %v", err)
	}
}

func TestCAFile(t *testing.T) {
	fx := newFixture(t)
	bad := newFixture(t)
	for name, tc := range map[string]struct {
		pem  []byte
		want string
	}{
		"not PEM":       {[]byte("hello"), "PEM block"},
		"key, not cert": {pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8(t, fx.caKey)}), "PEM block"},
		"two blocks":    {append(bytes.Clone(fx.caPEM), fx.caPEM...), "data after"},
		"not a CA": {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: func() []byte {
			ca, err := cert.NewCAFromDER(mustDER(t, bad.caPEM), bad.caKey)
			if err != nil {
				t.Fatal(err)
			}
			ca.Now = func() time.Time { return testNow }
			der, _, err := ca.Issue(&bad.passkeys[0].PublicKey, cert.Claims{User: "jack", Services: []string{"x"}})
			if err != nil {
				t.Fatal(err)
			}
			return der
		}()}), "CA"},
	} {
		fx := *fx
		fx.caPEM = tc.pem
		if _, err := fx.parse(t, fx.valid(t)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, tc.want)
		}
	}
}

func mustDER(t testing.TB, b []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("no PEM")
	}
	return block.Bytes
}

func TestLoadCA(t *testing.T) {
	fx := newFixture(t)
	c, err := fx.parse(t, fx.valid(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	keyPEM := func(k any) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8(t, k)})
	}

	ca, err := c.LoadCA(write("ok", keyPEM(fx.caKey)))
	if err != nil {
		t.Fatal(err)
	}
	if !ca.Key.Equal(fx.caKey) {
		t.Error("wrong key")
	}

	ecKey, err := x509.MarshalECPrivateKey(fx.caKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		pem  []byte
		want string
	}{
		"other key":   {keyPEM(fx.passkeys[0]), "doesn't match"},
		"SEC 1":       {pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecKey}), "PRIVATE KEY"},
		"P-384":       {keyPEM(fx.otherCurv), "doesn't match"},
		"garbage DER": {pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), "asn1"},
	} {
		if _, err := c.LoadCA(write(name, tc.pem)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, tc.want)
		}
	}
	if _, err := c.LoadCA(filepath.Join(dir, "absent")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("absent: %v", err)
	}
}
