package httpsig

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestParseSigInput(t *testing.T) {
	ok := []string{
		`sig1=("@method");created=1`,
		`sig1=()`,
		`a*.-_9=("x" "y z");n=0;s=""`,
		`*k=("a");created=999999999999999`,
	}
	for _, s := range ok {
		in, err := parseSigInput(s)
		if err != nil {
			t.Errorf("%s: %v", s, err)
			continue
		}
		if got := in.label + "=" + in.value(); got != s {
			t.Errorf("round trip %s -> %s", s, got)
		}
	}
	bad := []string{
		``,
		`sig1`,
		`Sig1=("a")`,                    // uppercase key
		`1sig=("a")`,                    // key starts with a digit
		`sig1=( "a")`,                   // leading space
		`sig1=("a" )`,                   // trailing space
		`sig1=("a"  "b")`,               // two spaces
		`sig1=("a""b")`,                 // no space
		`sig1=("a";x=1)`,                // item parameter
		`sig1=(a)`,                      // token
		`sig1=("a\"b")`,                 // escape
		"sig1=(\"a\tb\")",               // control character
		`sig1=("a")x`,                   // trailing garbage
		`sig1=("a") `,                   // trailing space
		`sig1=("a");x`,                  // boolean parameter
		`sig1=("a");x=?1`,               // boolean value
		`sig1=("a");x=1.5`,              // decimal
		`sig1=("a");x=-1`,               // negative
		`sig1=("a");x=01`,               // leading zero
		`sig1=("a");x=1000000000000000`, // 16 digits
		`sig1=("a");x=tok`,              // token value
		`sig1=("a"), sig2=("b")`,        // second member
		`sig1="a"`,                      // not an inner list
		`sig1=("a`,                      // unterminated
	}
	for _, s := range bad {
		if _, err := parseSigInput(s); err == nil {
			t.Errorf("%q parsed", s)
		}
	}
}

func TestParseBytes(t *testing.T) {
	for s, want := range map[string][]byte{
		`::`:     {},
		`:AA==:`: {0},
		`:AAAA:`: {0, 0, 0},
		`:/+8=:`: {0xff, 0xef},
	} {
		got, err := parseBytes(s)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s = %x, %v", s, got, err)
		}
	}
	for _, s := range []string{
		``, `:`, `AA==`, `:AA=:`, `:AA:`, `:_-8=:`, ":AA\n==:", `:AA==:x`, `:AB==:`,
	} {
		if _, err := parseBytes(s); err == nil {
			t.Errorf("%q parsed", s)
		}
	}
	if _, _, err := parseBytesMember(`sha-256=:AA==:`); err != nil {
		t.Error(err)
	}
	for _, s := range []string{`sha-256:AA==:`, `SHA-256=:AA==:`, `sha-256=:AA==:, sha-512=:AA==:`} {
		if _, _, err := parseBytesMember(s); err == nil {
			t.Errorf("%q parsed", s)
		}
	}
}

// FuzzParseSigInput checks that anything the parser accepts serializes back
// to exactly the input, so the @signature-params line is the header's value.
func FuzzParseSigInput(f *testing.F) {
	f.Add(`sig1=("@method" "@authority" "@path" "@query" "content-digest" "sso-cert");created=1800000000;expires=1800000060;nonce="AAAAAAAAAAAAAAAAAAAAAA";keyid="0a1b2c";tag="farm1-sso-v1"`)
	f.Add(`ttrp=("@path" "@query" "@method" "@authority" "client-cert");created=1618884473;keyid="test-key-ecc-p256"`)
	f.Add(`sig1=()`)
	f.Fuzz(func(t *testing.T, s string) {
		in, err := parseSigInput(s)
		if err != nil {
			return
		}
		if got := in.label + "=" + in.value(); got != s {
			t.Fatalf("round trip %q -> %q", s, got)
		}
		_, _ = profileParams(in)
	})
}

func FuzzParseBytes(f *testing.F) {
	f.Add(`sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:`)
	f.Add(`:c3RhbmQtaW4=:`)
	f.Fuzz(func(t *testing.T, s string) {
		if b, err := parseBytes(s); err == nil && serializeBytes(b) != s {
			t.Fatalf("round trip %q -> %q", s, serializeBytes(b))
		}
		if k, b, err := parseBytesMember(s); err == nil && k+"="+serializeBytes(b) != s {
			t.Fatalf("round trip %q -> %q", s, k+"="+serializeBytes(b))
		}
	})
}

// FuzzSignatureBase checks that no request can add or remove a line of the
// signature base: it's built with exactly one line per component or not at
// all.
func FuzzSignatureBase(f *testing.F) {
	f.Add("POST", "farm-1:9200", "/v1/microvms/web/restart", "force=1", "sha-256=:AA==:", ":AA==:")
	f.Add("GET", "x\ny", "/a%0Ab", "", "", "")
	f.Fuzz(func(t *testing.T, method, host, path, query, digest, cert string) {
		r := httptest.NewRequest(http.MethodGet, "http://example/", nil)
		r.Method, r.Host, r.URL.Path, r.URL.RawQuery = method, host, path, query
		r.Header[HeaderContentDigest] = []string{digest}
		r.Header[HeaderCert] = []string{cert}
		base, err := signatureBase(func(name string) (string, error) {
			return requestValue(r, name)
		}, components, "()")
		if err != nil {
			return
		}
		lines := strings.Split(string(base), "\n")
		if len(lines) != len(components)+1 {
			t.Fatalf("%d lines:\n%s", len(lines), base)
		}
		for i, name := range append(slices.Clone(components), "@signature-params") {
			if !strings.HasPrefix(lines[i], `"`+name+`": `) {
				t.Fatalf("line %d is %q", i, lines[i])
			}
		}
	})
}

// FuzzVerify feeds arbitrary signature headers, host, path and body to a
// write-route Verifier. It must never panic, and must only fail with a
// reason from the closed set.
func FuzzVerify(f *testing.F) {
	c := newCase(f)
	h := c.r.Header
	f.Add(h.Get(HeaderSignatureInput), h.Get(HeaderSignature), h.Get(HeaderContentDigest), h.Get(HeaderCert), c.r.Host, c.r.URL.RawPath, string(c.body))
	f.Fuzz(func(t *testing.T, input, sig, digest, cert, host, rawPath, body string) {
		c := newCase(t)
		c.r.Header.Set(HeaderSignatureInput, input)
		c.r.Header.Set(HeaderSignature, sig)
		c.r.Header.Set(HeaderContentDigest, digest)
		c.r.Header.Set(HeaderCert, cert)
		c.r.Host = host
		c.r.URL.RawPath = rawPath
		c.body = []byte(body)
		err := c.verify()
		if err != nil && !slices.Contains(Reasons(), ReasonOf(err)) {
			t.Fatalf("error outside the closed set: %v", err)
		}
	})
}
