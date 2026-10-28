package httpsig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Verifier checks signed requests. C is what Cert returns about the
// certificate (in practice the cert package's parsed certificate), handed back
// in Verified for the tier and role check.
type Verifier[C any] struct {
	// Authorities are the @authority values this service answers to, as
	// clients send them in Host (host, plus port if one is given). Requests for
	// any other name are rejected, so a request for one service can't be
	// replayed against another that the same certificate covers.
	Authorities []string
	// Cert verifies the certificate from the Sso-Cert header: chain to the CA,
	// expiry, this service and the source address, and keyID as its serial.
	// It returns the client's public key. An *Error with ReasonCert,
	// ReasonCertExpired or ReasonScope is passed through; any other error
	// becomes ReasonCert.
	Cert func(r *http.Request, der []byte, keyID string) (*ecdsa.PublicKey, C, error)
	// Nonces is set for write routes. Leave it nil for reads, which don't
	// change anything and so aren't worth a cache entry.
	Nonces *NonceCache
	// Started is when the service started. With Nonces set, signatures created
	// at or before it are rejected, since the nonce cache doesn't survive a
	// restart. (At the same second too, as created has no fraction.)
	Started time.Time
	Now     func() time.Time
}

// Verified is a request that passed every check.
type Verified[C any] struct {
	Params Params
	Cert   C
}

// parsed holds the signature headers of a request, checked against the
// profile, and the signature base rebuilt from it.
type parsed struct {
	params Params
	sig    []byte
	digest []byte
	cert   []byte
	base   []byte
}

// Verify checks r, whose body has already been read into body (the caller
// sets the size limit). The order is cheapest first, and the nonce comes last
// so only a correctly signed request can take a slot in the cache.
func (v *Verifier[C]) Verify(r *http.Request, body []byte) (*Verified[C], error) {
	m, err := parse(r)
	if err != nil {
		return nil, err
	}
	p := m.params
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if err := v.checkWindow(p, now); err != nil {
		return nil, err
	}
	if p.Tag != Tag {
		return nil, fail(ReasonTag, "tag %q", p.Tag)
	}
	authority, _ := requestValue(r, "@authority") // checked while building the base
	if !slices.ContainsFunc(v.Authorities, func(a string) bool { return strings.EqualFold(a, authority) }) {
		return nil, fail(ReasonAuthority, "authority %q", authority)
	}
	pub, cert, err := v.Cert(r, m.cert, p.KeyID)
	if err != nil {
		var e *Error
		if errors.As(err, &e) && slices.Contains(certReasons, e.Reason) {
			return nil, e
		}
		return nil, &Error{Reason: ReasonCert, Err: err}
	}
	if h := sha256.Sum256(body); !bytes.Equal(h[:], m.digest) {
		return nil, fail(ReasonDigest, "body doesn't match Content-Digest")
	}
	if !verifyES256(pub, m.base, m.sig) {
		return nil, &Error{Reason: ReasonSigMismatch, Base: m.base}
	}
	if v.Nonces != nil {
		until := time.Unix(p.Created, 0).Add(Skew)
		if err := v.Nonces.use(p.KeyID, p.Nonce, until, now); err != nil {
			return nil, err
		}
	}
	return &Verified[C]{Params: p, Cert: cert}, nil
}

func (v *Verifier[C]) checkWindow(p Params, now time.Time) *Error {
	skew := int64(Skew / time.Second)
	t := now.Unix()
	switch {
	case p.Created < t-skew || p.Expires < t-skew:
		return fail(ReasonExpired, "created %d, expires %d, now %d", p.Created, p.Expires, t)
	case p.Created > t+skew:
		return fail(ReasonNotYetValid, "created %d, now %d", p.Created, t)
	case v.Nonces != nil && p.Created <= v.Started.Unix():
		return fail(ReasonBeforeStart, "created %d, started %d", p.Created, v.Started.Unix())
	}
	return nil
}

func parse(r *http.Request) (*parsed, error) {
	h := map[string]string{}
	for name, max := range maxHeader {
		vals := r.Header.Values(name)
		if len(vals) != 1 {
			return nil, fail(ReasonMalformed, "%s: %d header fields, want 1", name, len(vals))
		}
		if len(vals[0]) > max {
			return nil, fail(ReasonMalformed, "%s: %d bytes, limit %d", name, len(vals[0]), max)
		}
		h[name] = strings.Trim(vals[0], " \t")
	}

	in, err := parseSigInput(h[HeaderSignatureInput])
	if err != nil {
		return nil, fail(ReasonMalformed, "%s: %v", HeaderSignatureInput, err)
	}
	label, sig, err := parseBytesMember(h[HeaderSignature])
	if err != nil {
		return nil, fail(ReasonMalformed, "%s: %v", HeaderSignature, err)
	}
	alg, digest, err := parseBytesMember(h[HeaderContentDigest])
	if err != nil {
		return nil, fail(ReasonMalformed, "%s: %v", HeaderContentDigest, err)
	}
	cert, err := parseBytes(h[HeaderCert])
	if err != nil {
		return nil, fail(ReasonMalformed, "%s: %v", HeaderCert, err)
	}

	p, e := profileParams(in)
	if e != nil {
		return nil, e
	}
	if label != Label {
		return nil, fail(ReasonProfile, "%s label %q", HeaderSignature, label)
	}
	if alg != "sha-256" {
		return nil, fail(ReasonProfile, "%s algorithm %q", HeaderContentDigest, alg)
	}

	base, err := signatureBase(func(name string) (string, error) {
		return requestValue(r, name)
	}, components, in.value())
	if err != nil {
		return nil, fail(ReasonMalformed, "signature base: %v", err)
	}
	return &parsed{params: p, sig: sig, digest: digest, cert: cert, base: base}, nil
}
