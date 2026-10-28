package httpsig

import (
	"crypto/sha256"
	"slices"
	"time"
)

// The fixed profile (docs/design.md, "Protocol profile"). There is nothing to
// negotiate: a request that differs in any of these is rejected.
const (
	Label = "sig1"
	// Tag keeps a signature made for this protocol from being accepted by
	// another one that signs the same components.
	Tag = "farm1-sso-v1"
	// MaxLifetime caps expires - created.
	MaxLifetime = 300 * time.Second
	// Skew is how far created may be from the verifier's clock either way.
	Skew = 5 * time.Minute
	// lifetime is what Signer uses for expires - created.
	lifetime = 60 * time.Second
)

// Header names.
const (
	HeaderSignatureInput = "Signature-Input"
	HeaderSignature      = "Signature"
	HeaderContentDigest  = "Content-Digest"
	HeaderCert           = "Sso-Cert"
)

// components are the covered components, in this order and no others.
var components = []string{"@method", "@authority", "@path", "@query", "content-digest", "sso-cert"}

// Header size limits, checked before parsing. Each is several times what the
// profile produces; a certificate with a few passkey keys is about 1 KiB.
var maxHeader = map[string]int{
	HeaderSignatureInput: 512,
	HeaderSignature:      128,
	HeaderContentDigest:  128,
	HeaderCert:           8192,
}

const (
	minNonce = 16
	maxNonce = 64
	maxKeyID = 64
)

// Params are the signature parameters, in the order they're serialized.
type Params struct {
	Created int64 // Unix seconds
	Expires int64
	Nonce   string
	KeyID   string // the certificate serial
	Tag     string
}

func (p Params) list() []param {
	return []param{
		{key: "created", num: p.Created, isNum: true},
		{key: "expires", num: p.Expires, isNum: true},
		{key: "nonce", str: p.Nonce},
		{key: "keyid", str: p.KeyID},
		{key: "tag", str: p.Tag},
	}
}

// profileParams checks that in is the profile's Signature-Input, apart from
// the tag's value (its own step and reason), and returns its parameters.
func profileParams(in sigInput) (Params, *Error) {
	if in.label != Label {
		return Params{}, fail(ReasonProfile, "label %q", in.label)
	}
	if !slices.Equal(in.items, components) {
		return Params{}, fail(ReasonProfile, "components %q", in.items)
	}
	want := Params{}.list()
	if len(in.params) != len(want) {
		return Params{}, fail(ReasonProfile, "%d parameters, want %d", len(in.params), len(want))
	}
	for i, p := range in.params {
		if p.key != want[i].key || p.isNum != want[i].isNum {
			return Params{}, fail(ReasonProfile, "parameter %d is %q, want %q", i, p.key, want[i].key)
		}
	}
	p := Params{
		Created: in.params[0].num,
		Expires: in.params[1].num,
		Nonce:   in.params[2].str,
		KeyID:   in.params[3].str,
		Tag:     in.params[4].str,
	}
	switch {
	case p.Expires <= p.Created || p.Expires-p.Created > int64(MaxLifetime/time.Second):
		return Params{}, fail(ReasonProfile, "expires - created = %d", p.Expires-p.Created)
	case len(p.Nonce) < minNonce || len(p.Nonce) > maxNonce:
		return Params{}, fail(ReasonProfile, "nonce length %d", len(p.Nonce))
	case p.KeyID == "" || len(p.KeyID) > maxKeyID:
		return Params{}, fail(ReasonProfile, "keyid length %d", len(p.KeyID))
	}
	return p, nil
}

// ContentDigest returns the Content-Digest value for body (RFC 9530, SHA-256).
// It's sent and covered even when the body is empty.
func ContentDigest(body []byte) string {
	h := sha256.Sum256(body)
	return "sha-256=" + serializeBytes(h[:])
}
