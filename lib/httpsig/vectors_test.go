package httpsig

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Test vectors from RFC 9421 Appendix B and RFC 9530 Appendix B. Lines that
// the RFCs wrap with '\' (RFC 8792) are joined here.

// testKeyECCP256 is test-key-ecc-p256 (RFC 9421 B.1.3).
const testKeyECCP256 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49
AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM
4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END EC PRIVATE KEY-----`

const testPubECCP256 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END PUBLIC KEY-----`

func testKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode([]byte(testKeyECCP256))
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// testPub parses the RFC's public key separately, so the vectors don't only
// check that the private key matches itself.
func testPub(t testing.TB) *ecdsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(testPubECCP256))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return pub.(*ecdsa.PublicKey)
}

func TestTestKeysMatch(t *testing.T) {
	if !testKey(t).PublicKey.Equal(testPub(t)) {
		t.Fatal("B.1.3 public key doesn't match the private key")
	}
}

// B.2.4: a response signed with ecdsa-p256-sha256. It uses @status, which
// requests don't have, so it checks the generic parser, base builder and
// signature encoding rather than requestValue.
func TestRFC9421B24(t *testing.T) {
	const (
		input = `sig-b24=("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"`
		sig   = `sig-b24=:wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==:`
		base  = `"@status": 200
"content-type": application/json
"content-digest": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:
"content-length": 23
"@signature-params": ("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"`
	)
	values := map[string]string{
		"@status":        "200",
		"content-type":   "application/json",
		"content-digest": "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:",
		"content-length": "23",
	}

	in, err := parseSigInput(input)
	if err != nil {
		t.Fatal(err)
	}
	if got := in.label + "=" + in.value(); got != input {
		t.Fatalf("Signature-Input round trip:\n got %s\nwant %s", got, input)
	}
	got, err := signatureBase(func(name string) (string, error) {
		v, ok := values[name]
		if !ok {
			return "", fmt.Errorf("no %s", name)
		}
		return v, nil
	}, in.items, in.value())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != base {
		t.Fatalf("signature base:\n%s\nwant:\n%s", got, base)
	}
	label, raw, err := parseBytesMember(sig)
	if err != nil || label != "sig-b24" {
		t.Fatalf("Signature: %q %v", label, err)
	}
	if !verifyES256(testPub(t), got, raw) {
		t.Fatal("B.2.4 signature doesn't verify")
	}
}

// B.3: a TLS-terminating proxy signs a request with ecdsa-p256-sha256,
// covering @path, @query, @method, @authority and a certificate header. That
// is close to the profile, so this runs through requestValue on a real
// server-side request.
func TestRFC9421B3(t *testing.T) {
	const clientCert = `:MIIBqDCCAU6gAwIBAgIBBzAKBggqhkjOPQQDAjA6MRswGQYDVQQKDBJMZXQncyBBdXRoZW50aWNhdGUxGzAZBgNVBAMMEkxBIEludGVybWVkaWF0ZSBDQTAeFw0yMDAxMTQyMjU1MzNaFw0yMTAxMjMyMjU1MzNaMA0xCzAJBgNVBAMMAkJDMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8YnXXfaUgmnMtOXU/IncWalRhebrXmckC8vdgJ1p5Be5F/3YC8OthxM4+k1M6aEAEFcGzkJiNy6J84y7uzo9M6NyMHAwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBRm3WjLa38lbEYCuiCPct0ZaSED2DAOBgNVHQ8BAf8EBAMCBsAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0RAQH/BBMwEYEPYmRjQGV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIBHda/r1vaL6G3VliL4/Di6YK0Q6bMjeSkC3dFCOOB8TAiEAx/kHSB4urmiZ0NX5r5XarmPk0wmuydBVoU4hBVZ1yhk=:`
	const (
		input = `ttrp=("@path" "@query" "@method" "@authority" "client-cert");created=1618884473;keyid="test-key-ecc-p256"`
		sig   = `ttrp=:xVMHVpawaAC/0SbHrKRs9i8I3eOs5RtTMGCWXm/9nvZzoHsIg6Mce9315T6xoklyy0yzhD9ah4JHRwMLOgmizw==:`
		base  = `"@path": /foo
"@query": ?param=Value&Pet=dog
"@method": POST
"@authority": service.internal.example
"client-cert": ` + clientCert + `
"@signature-params": ("@path" "@query" "@method" "@authority" "client-cert");created=1618884473;keyid="test-key-ecc-p256"`
	)
	raw := "POST /foo?param=Value&Pet=dog HTTP/1.1\r\n" +
		"Host: service.internal.example\r\n" +
		"Date: Tue, 20 Apr 2021 02:07:55 GMT\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 18\r\n" +
		"Client-Cert: " + clientCert + "\r\n" +
		"Signature-Input: " + input + "\r\n" +
		"Signature: " + sig + "\r\n\r\n" +
		`{"hello": "world"}`
	r := readRequest(t, raw)

	in, err := parseSigInput(r.Header.Get("Signature-Input"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := signatureBase(func(name string) (string, error) {
		return requestValue(r, name)
	}, in.items, in.value())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != base {
		t.Fatalf("signature base:\n%s\nwant:\n%s", got, base)
	}
	_, s, err := parseBytesMember(r.Header.Get("Signature"))
	if err != nil {
		t.Fatal(err)
	}
	if !verifyES256(testPub(t), got, s) {
		t.Fatal("B.3 signature doesn't verify")
	}
}

// RFC 9530 B.1 and B.2: {"hello": "world"} plus LF, and empty content.
func TestRFC9530ContentDigest(t *testing.T) {
	for body, want := range map[string]string{
		"{\"hello\": \"world\"}\n": "sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:",
		"":                         "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
	} {
		if got := ContentDigest([]byte(body)); got != want {
			t.Errorf("ContentDigest(%q) = %s, want %s", body, got, want)
		}
	}
}

func readRequest(t testing.TB, raw string) *http.Request {
	t.Helper()
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
