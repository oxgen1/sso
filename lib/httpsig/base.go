package httpsig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
)

// signatureBase builds the RFC 9421 section 2.5 signature base: one
// `"name": value` line per covered component, then the @signature-params
// line, with no trailing newline.
func signatureBase(value func(name string) (string, error), items []string, sigParams string) ([]byte, error) {
	var b bytes.Buffer
	for i, name := range items {
		if slices.Contains(items[:i], name) {
			return nil, fmt.Errorf("%s covered twice", name)
		}
		v, err := value(name)
		if err != nil {
			return nil, err
		}
		b.WriteString(`"` + name + `": ` + v + "\n")
	}
	b.WriteString(`"@signature-params": ` + sigParams)
	return b.Bytes(), nil
}

// requestValue returns a covered component of r, the same way for a client
// request (signing) and a server request (verifying).
//
// @authority is the Host header lowercased, with the port kept as sent: RFC
// 9421 drops a default port, but mvm and statusd never use one, and keeping
// it means a verifier needn't know the scheme. Header fields must appear
// exactly once rather than being joined, as nothing in the profile repeats.
func requestValue(r *http.Request, name string) (string, error) {
	var v string
	switch name {
	case "@method":
		v = r.Method
		if v == "" {
			v = http.MethodGet
		}
	case "@authority":
		v = r.Host
		if v == "" {
			v = r.URL.Host
		}
		v = strings.ToLower(v)
	case "@path":
		v = r.URL.EscapedPath()
		if v == "" {
			v = "/"
		}
	case "@query":
		v = "?" + r.URL.RawQuery
	default:
		if strings.HasPrefix(name, "@") {
			return "", fmt.Errorf("unsupported component %s", name)
		}
		vals := r.Header.Values(name)
		if len(vals) != 1 {
			return "", fmt.Errorf("%s: %d header fields, want 1", name, len(vals))
		}
		v = strings.Trim(vals[0], " \t")
	}
	// A newline would let a value forge the next line of the base. Go's server
	// already refuses them in headers, but a client can put anything in Host.
	for i := range len(v) {
		if v[i] < 0x20 || v[i] > 0x7e {
			return "", fmt.Errorf("%s: byte %#x not allowed", name, v[i])
		}
	}
	return v, nil
}

// signES256 and verifyES256 use the RFC 9421 section 3.3.4 encoding: r and s
// as 32-byte big-endian integers, concatenated (not ASN.1).
func signES256(key *ecdsa.PrivateKey, base []byte) ([]byte, error) {
	if key.Curve != elliptic.P256() {
		return nil, errors.New("httpsig: key is not P-256")
	}
	h := sha256.Sum256(base)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

func verifyES256(pub *ecdsa.PublicKey, base, sig []byte) bool {
	if pub == nil || pub.Curve != elliptic.P256() || len(sig) != 64 {
		return false
	}
	h := sha256.Sum256(base)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, h[:], r, s)
}

// BaseHash is what the diagnostic log records on ReasonSigMismatch, and what
// mvm prints for the base it signed. Different hashes mean the two sides
// wrote the request down differently; equal ones mean the wrong key.
func BaseHash(base []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(base))
}
