package httpsig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var (
	testNow     = time.Unix(1_800_000_000, 0)
	testStarted = testNow.Add(-time.Hour)
	testCertDER = []byte("stand-in for a DER certificate")
)

const (
	testAuthority = "farm-1:9200"
	testKeyID     = "0a1b2c"
	testNonce     = "AAAAAAAAAAAAAAAAAAAAAA"
)

// testCase is a request signed by testSigner, the body that goes with it, and
// a Verifier for a write route that accepts it.
type testCase struct {
	t      testing.TB
	r      *http.Request
	body   []byte
	v      *Verifier[string]
	signer *Signer
}

func newCase(t testing.TB) *testCase {
	t.Helper()
	key := testKey(t)
	c := &testCase{
		t:      t,
		body:   []byte(`{"vm":"web"}`),
		signer: &Signer{Key: key, Cert: testCertDER, KeyID: testKeyID, Now: func() time.Time { return testNow }},
		v: &Verifier[string]{
			Authorities: []string{testAuthority},
			Cert: func(_ *http.Request, der []byte, keyID string) (*ecdsa.PublicKey, string, error) {
				if !bytes.Equal(der, testCertDER) || keyID != testKeyID {
					return nil, "", fail(ReasonCert, "unknown certificate")
				}
				return &key.PublicKey, "jack", nil
			},
			Nonces:  NewNonceCache(8),
			Started: testStarted,
			Now:     func() time.Time { return testNow },
		},
	}
	c.r = c.request()
	if _, err := c.signer.Sign(c.r, c.body); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *testCase) request() *http.Request {
	return httptest.NewRequest(http.MethodPost, "http://"+testAuthority+"/v1/microvms/web/restart?force=1", bytes.NewReader(c.body))
}

// resign signs a fresh request with the given parameters, label and
// components, so a test can reach the checks after the signature parse.
func (c *testCase) resign(label string, items []string, p Params) {
	c.t.Helper()
	c.r = c.request()
	if _, err := c.signer.sign(c.r, c.body, label, items, p.list()); err != nil {
		c.t.Fatal(err)
	}
}

func validParams() Params {
	return Params{
		Created: testNow.Unix(),
		Expires: testNow.Unix() + 60,
		Nonce:   testNonce,
		KeyID:   testKeyID,
		Tag:     Tag,
	}
}

func (c *testCase) verify() error {
	_, err := c.v.Verify(c.r, c.body)
	return err
}

func TestSignVerify(t *testing.T) {
	c := newCase(t)
	got, err := c.v.Verify(c.r, c.body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cert != "jack" || got.Params.KeyID != testKeyID || got.Params.Tag != Tag ||
		got.Params.Created != testNow.Unix() || got.Params.Expires != testNow.Unix()+60 {
		t.Fatalf("Verified = %+v", got)
	}
	if n := len(got.Params.Nonce); n != 22 {
		t.Fatalf("nonce %q has length %d, want 22", got.Params.Nonce, n)
	}
}

func TestReadRouteSkipsNonce(t *testing.T) {
	c := newCase(t)
	c.v.Nonces = nil
	c.v.Started = testNow // only matters with a nonce cache
	for range 2 {
		if err := c.verify(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEmptyBody(t *testing.T) {
	c := newCase(t)
	c.body = nil
	c.r = httptest.NewRequest(http.MethodGet, "http://"+testAuthority+"/v1/status", nil)
	if _, err := c.signer.Sign(c.r, nil); err != nil {
		t.Fatal(err)
	}
	if got := c.r.Header.Get(HeaderContentDigest); got != "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:" {
		t.Fatalf("Content-Digest = %s", got)
	}
	if err := c.verify(); err != nil {
		t.Fatal(err)
	}
}

// TestGoldenBase pins the exact signature base the profile produces. If it
// changes, every deployed verifier disagrees with the new signer, so this
// should only change with a new Tag.
func TestGoldenBase(t *testing.T) {
	c := newCase(t)
	r := c.request()
	base, err := c.signer.sign(r, c.body, Label, components, validParams().list())
	if err != nil {
		t.Fatal(err)
	}
	const want = `"@method": POST
"@authority": farm-1:9200
"@path": /v1/microvms/web/restart
"@query": ?force=1
"content-digest": sha-256=:CYRtpUJwcwKtwF5Hf4Ct3wKvCBNoKJXjDAXEJj7PqXc=:
"sso-cert": :c3RhbmQtaW4gZm9yIGEgREVSIGNlcnRpZmljYXRl:
"@signature-params": ("@method" "@authority" "@path" "@query" "content-digest" "sso-cert");created=1800000000;expires=1800000060;nonce="AAAAAAAAAAAAAAAAAAAAAA";keyid="0a1b2c";tag="farm1-sso-v1"`
	if string(base) != want {
		t.Fatalf("signature base:\n%s\nwant:\n%s", base, want)
	}
	if got := r.Header.Get(HeaderSignatureInput); got != "sig1="+strings.TrimPrefix(want[strings.LastIndex(want, "\n")+1:], `"@signature-params": `) {
		t.Fatalf("Signature-Input = %s", got)
	}
}

// mutations each change one thing about a valid request and name the reason
// it must fail with. TestEveryReasonCovered checks that every Reason has one.
var mutations = []struct {
	name   string
	mutate func(c *testCase)
	want   Reason
}{
	// Parse.
	{"no Signature-Input", func(c *testCase) { c.r.Header.Del(HeaderSignatureInput) }, ReasonMalformed},
	{"no Signature", func(c *testCase) { c.r.Header.Del(HeaderSignature) }, ReasonMalformed},
	{"no Content-Digest", func(c *testCase) { c.r.Header.Del(HeaderContentDigest) }, ReasonMalformed},
	{"no Sso-Cert", func(c *testCase) { c.r.Header.Del(HeaderCert) }, ReasonMalformed},
	{"two Signature headers", func(c *testCase) { c.r.Header.Add(HeaderSignature, c.r.Header.Get(HeaderSignature)) }, ReasonMalformed},
	{"two Sso-Cert headers", func(c *testCase) { c.r.Header.Add(HeaderCert, c.r.Header.Get(HeaderCert)) }, ReasonMalformed},
	{"oversized Sso-Cert", func(c *testCase) { c.r.Header.Set(HeaderCert, serializeBytes(make([]byte, 8192))) }, ReasonMalformed},
	{"two signatures in one header", func(c *testCase) {
		c.r.Header.Set(HeaderSignature, c.r.Header.Get(HeaderSignature)+", sig2=:AAAA:")
	}, ReasonMalformed},
	{"escaped string", func(c *testCase) {
		c.r.Header.Set(HeaderSignatureInput, strings.Replace(c.r.Header.Get(HeaderSignatureInput), `"@method"`, `"@meth\od"`, 1))
	}, ReasonMalformed},
	{"double space in inner list", func(c *testCase) {
		c.r.Header.Set(HeaderSignatureInput, strings.Replace(c.r.Header.Get(HeaderSignatureInput), `" "`, `"  "`, 1))
	}, ReasonMalformed},
	{"boolean parameter", func(c *testCase) {
		c.r.Header.Set(HeaderSignatureInput, c.r.Header.Get(HeaderSignatureInput)+";x")
	}, ReasonMalformed},
	{"unpadded base64", func(c *testCase) {
		// A 64-byte signature has "==" padding.
		c.r.Header.Set(HeaderSignature, strings.TrimRight(c.r.Header.Get(HeaderSignature), ":=")+":")
	}, ReasonMalformed},
	{"newline in Host", func(c *testCase) { c.r.Host = "farm-1:9200\nx" }, ReasonMalformed},
	{"wrong label", func(c *testCase) { c.resign("sig2", components, validParams()) }, ReasonProfile},
	{"Signature label differs", func(c *testCase) {
		c.r.Header.Set(HeaderSignature, "sig2"+strings.TrimPrefix(c.r.Header.Get(HeaderSignature), "sig1"))
	}, ReasonProfile},
	{"component missing", func(c *testCase) { c.resign(Label, components[:5], validParams()) }, ReasonProfile},
	{"components reordered", func(c *testCase) {
		c.resign(Label, []string{"@authority", "@method", "@path", "@query", "content-digest", "sso-cert"}, validParams())
	}, ReasonProfile},
	{"extra alg parameter", func(c *testCase) {
		c.r.Header.Set(HeaderSignatureInput, c.r.Header.Get(HeaderSignatureInput)+`;alg="ecdsa-p256-sha256"`)
	}, ReasonProfile},
	{"expires before created", func(c *testCase) {
		p := validParams()
		p.Expires = p.Created
		c.resign(Label, components, p)
	}, ReasonProfile},
	{"lifetime over 300 s", func(c *testCase) {
		p := validParams()
		p.Expires = p.Created + 301
		c.resign(Label, components, p)
	}, ReasonProfile},
	{"short nonce", func(c *testCase) {
		p := validParams()
		p.Nonce = "abc"
		c.resign(Label, components, p)
	}, ReasonProfile},
	{"empty keyid", func(c *testCase) {
		p := validParams()
		p.KeyID = ""
		c.resign(Label, components, p)
	}, ReasonProfile},
	{"Content-Digest sha-512", func(c *testCase) {
		c.r.Header.Set(HeaderContentDigest, "sha-512="+serializeBytes(make([]byte, 64)))
	}, ReasonProfile},

	// Time.
	{"created 5 min 1 s ago", func(c *testCase) { c.v.Now = func() time.Time { return testNow.Add(Skew + time.Second) } }, ReasonExpired},
	{"expired beyond skew", func(c *testCase) {
		p := validParams()
		p.Created -= 60
		p.Expires = p.Created + 1
		c.resign(Label, components, p)
		c.v.Now = func() time.Time { return testNow.Add(Skew - 58*time.Second) }
	}, ReasonExpired},
	{"created 5 min 1 s ahead", func(c *testCase) { c.v.Now = func() time.Time { return testNow.Add(-Skew - time.Second) } }, ReasonNotYetValid},
	{"signed before restart", func(c *testCase) { c.v.Started = testNow }, ReasonBeforeStart},

	{"wrong tag", func(c *testCase) {
		p := validParams()
		p.Tag = "farm1-sso-v0"
		c.resign(Label, components, p)
	}, ReasonTag},
	{"other service", func(c *testCase) { c.v.Authorities = []string{"farm-2:9200"} }, ReasonAuthority},

	// Certificate.
	{"unknown certificate", func(c *testCase) { c.r.Header.Set(HeaderCert, serializeBytes([]byte("other"))) }, ReasonCert},
	{"keyid isn't the serial", func(c *testCase) {
		p := validParams()
		p.KeyID = "ffff"
		c.resign(Label, components, p)
	}, ReasonCert},
	{"Cert returns a plain error", func(c *testCase) {
		c.v.Cert = func(*http.Request, []byte, string) (*ecdsa.PublicKey, string, error) {
			return nil, "", errors.New("parse error")
		}
	}, ReasonCert},
	{"Cert returns a reason it doesn't own", func(c *testCase) {
		c.v.Cert = func(*http.Request, []byte, string) (*ecdsa.PublicKey, string, error) {
			return nil, "", fail(ReasonReplay, "not a certificate reason")
		}
	}, ReasonCert},
	{"certificate expired", func(c *testCase) {
		c.v.Cert = func(*http.Request, []byte, string) (*ecdsa.PublicKey, string, error) {
			return nil, "", fail(ReasonCertExpired, "expired")
		}
	}, ReasonCertExpired},
	{"certificate for another service", func(c *testCase) {
		c.v.Cert = func(*http.Request, []byte, string) (*ecdsa.PublicKey, string, error) {
			return nil, "", fail(ReasonScope, "farm-2 only")
		}
	}, ReasonScope},

	// Body.
	{"body changed", func(c *testCase) { c.body = []byte(`{"vm":"db"}`) }, ReasonDigest},
	{"body dropped", func(c *testCase) { c.body = nil }, ReasonDigest},

	// Signature: every covered component, and the signature itself.
	{"method changed", func(c *testCase) { c.r.Method = http.MethodDelete }, ReasonSigMismatch},
	{"authority changed", func(c *testCase) {
		c.r.Host = "farm-1:9201"
		c.v.Authorities = append(c.v.Authorities, "farm-1:9201")
	}, ReasonSigMismatch},
	{"authority case is folded", func(c *testCase) {
		// Not a mismatch: @authority is lowercased on both sides.
		c.r.Host = "FARM-1:9200"
		c.v.Nonces = nil
		c.v.Cert = func(*http.Request, []byte, string) (*ecdsa.PublicKey, string, error) {
			return nil, "", fail(ReasonScope, "reached the certificate check")
		}
	}, ReasonScope},
	{"path changed", func(c *testCase) { c.r.URL.Path = "/v1/microvms/db/restart" }, ReasonSigMismatch},
	{"path escaped differently", func(c *testCase) { c.r.URL.RawPath = "/v1/microvms/w%65b/restart" }, ReasonSigMismatch},
	{"query changed", func(c *testCase) { c.r.URL.RawQuery = "force=0" }, ReasonSigMismatch},
	{"query dropped", func(c *testCase) { c.r.URL.RawQuery = "" }, ReasonSigMismatch},
	{"digest and body changed together", func(c *testCase) {
		c.body = []byte(`{"vm":"db"}`)
		c.r.Header.Set(HeaderContentDigest, ContentDigest(c.body))
	}, ReasonSigMismatch},
	{"certificate swapped", func(c *testCase) {
		c.r.Header.Set(HeaderCert, serializeBytes([]byte("other")))
		c.v.Cert = func(*http.Request, []byte, string) (*ecdsa.PublicKey, string, error) {
			return &testKey(c.t).PublicKey, "", nil
		}
	}, ReasonSigMismatch},
	{"nonce changed", func(c *testCase) {
		c.r.Header.Set(HeaderSignatureInput, strings.Replace(c.r.Header.Get(HeaderSignatureInput), `nonce="`, `nonce="x`, 1))
	}, ReasonSigMismatch},
	{"expires extended", func(c *testCase) {
		c.r.Header.Set(HeaderSignatureInput, strings.Replace(c.r.Header.Get(HeaderSignatureInput), "expires=1800000060", "expires=1800000300", 1))
	}, ReasonSigMismatch},
	{"signature bit flipped", func(c *testCase) {
		_, sig, _ := parseBytesMember(c.r.Header.Get(HeaderSignature))
		sig[10] ^= 1
		c.r.Header.Set(HeaderSignature, Label+"="+serializeBytes(sig))
	}, ReasonSigMismatch},
	{"signature in ASN.1", func(c *testCase) {
		c.r.Header.Set(HeaderSignature, Label+"="+serializeBytes(make([]byte, 72)))
	}, ReasonSigMismatch},
	{"other key", func(c *testCase) {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			c.t.Fatal(err)
		}
		c.signer.Key = other
		c.r = c.request()
		if _, err := c.signer.Sign(c.r, c.body); err != nil {
			c.t.Fatal(err)
		}
	}, ReasonSigMismatch},
	{"P-384 key", func(c *testCase) {
		other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			c.t.Fatal(err)
		}
		c.v.Cert = func(*http.Request, []byte, string) (*ecdsa.PublicKey, string, error) {
			return &other.PublicKey, "", nil
		}
	}, ReasonSigMismatch},

	// Nonce.
	{"replayed", func(c *testCase) {
		if err := c.verify(); err != nil {
			c.t.Fatal(err)
		}
	}, ReasonReplay},
	{"nonce cache full", func(c *testCase) {
		c.v.Nonces = NewNonceCache(1)
		if err := c.v.Nonces.use("other", testNonce, testNow.Add(time.Minute), testNow); err != nil {
			c.t.Fatal(err)
		}
	}, ReasonNonceFull},
}

func TestMutations(t *testing.T) {
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			c := newCase(t)
			m.mutate(c)
			err := c.verify()
			if got := ReasonOf(err); got != m.want {
				t.Fatalf("reason %q (%v), want %q", got, err, m.want)
			}
		})
	}
}

func TestEveryReasonCovered(t *testing.T) {
	covered := map[Reason]bool{}
	for _, m := range mutations {
		covered[m.want] = true
	}
	for _, r := range Reasons() {
		if !covered[r] {
			t.Errorf("no mutation produces %q", r)
		}
	}
	if len(covered) != len(Reasons()) {
		t.Errorf("mutations name %d reasons, Reasons has %d", len(covered), len(Reasons()))
	}
}

func TestSigMismatchCarriesBase(t *testing.T) {
	c := newCase(t)
	c.r.Method = http.MethodPut
	var e *Error
	if !errors.As(c.verify(), &e) || e.Reason != ReasonSigMismatch {
		t.Fatalf("want sig_mismatch")
	}
	if !bytes.HasPrefix(e.Base, []byte(`"@method": PUT`+"\n")) {
		t.Fatalf("Base = %q", e.Base)
	}
	if len(BaseHash(e.Base)) != 64 {
		t.Fatalf("BaseHash = %q", BaseHash(e.Base))
	}
}

func TestNonceCacheExpiry(t *testing.T) {
	n := NewNonceCache(1)
	if err := n.use("k", "a", testNow.Add(time.Minute), testNow); err != nil {
		t.Fatal(err)
	}
	if err := n.use("k", "b", testNow.Add(2*time.Minute), testNow); ReasonOf(err) != ReasonNonceFull {
		t.Fatalf("second live nonce: %v", err)
	}
	// Once the first entry can no longer pass the window, it's swept.
	later := testNow.Add(time.Minute)
	if err := n.use("k", "b", later.Add(time.Minute), later); err != nil {
		t.Fatal(err)
	}
	// The same nonce under another certificate is a different entry.
	n = NewNonceCache(2)
	if err := n.use("k1", "a", later, testNow); err != nil {
		t.Fatal(err)
	}
	if err := n.use("k2", "a", later, testNow); err != nil {
		t.Fatal(err)
	}
}

func TestSignerRejects(t *testing.T) {
	key := testKey(t)
	r := httptest.NewRequest(http.MethodGet, "http://"+testAuthority+"/", nil)
	if _, err := (&Signer{Key: key, KeyID: `bad"id`}).Sign(r, nil); err == nil {
		t.Error("keyid with a quote was signed")
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&Signer{Key: p384, KeyID: testKeyID}).Sign(r, nil); err == nil {
		t.Error("P-384 key was used")
	}
}
