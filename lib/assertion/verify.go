package assertion

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/oxgen1/sso/lib/cert"
	"github.com/oxgen1/sso/lib/httpsig"
)

// authenticatorData flags (WebAuthn §6.1). Backup eligibility and state (bits
// 3 and 4) and the reserved bits are ignored, as the spec asks.
const (
	flagUP = 1 << 0 // user present
	flagUV = 1 << 2 // user verified
	flagAT = 1 << 6 // attested credential data follows
	flagED = 1 << 7 // extensions follow
)

// authDataLen is rpIdHash (32), flags (1) and signCount (4). An assertion has
// no attested credential data, and the approval page asks for no extensions,
// so nothing follows.
const authDataLen = 37

// Challenge is the WebAuthn challenge for a request: SHA-256 of its signature
// base. The approval page passes it to navigator.credentials.get.
func Challenge(base []byte) []byte {
	h := sha256.Sum256(base)
	return h[:]
}

// Verifier checks assertions made on the IdP's approval page.
type Verifier struct {
	rpIDHash [32]byte
	origin   string
}

// NewVerifier returns a Verifier for passkeys bound to rpID, used on the page
// at origin, which must be https on rpID or a subdomain of it, with no port.
func NewVerifier(rpID, origin string) (*Verifier, error) {
	if !validHost(rpID) {
		return nil, fmt.Errorf("RP ID %q isn't a lowercase DNS name", rpID)
	}
	host, ok := strings.CutPrefix(origin, "https://")
	if !ok || !validHost(host) {
		return nil, fmt.Errorf("origin %q isn't https://<lowercase DNS name>", origin)
	}
	if host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return nil, fmt.Errorf("origin %q isn't on RP ID %q", origin, rpID)
	}
	return &Verifier{rpIDHash: sha256.Sum256([]byte(rpID)), origin: origin}, nil
}

// validHost reports whether s is dot-separated labels of lowercase letters,
// digits and hyphens. That also means the origin needs no escaping in JSON.
func validHost(s string) bool {
	labels := strings.Split(s, ".")
	return len(s) <= 253 && !slices.ContainsFunc(labels, func(l string) bool {
		return l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' ||
			strings.ContainsFunc(l, func(c rune) bool {
				return (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-'
			})
	})
}

// Verify checks the Sso-Assertion header of r, a request the service's
// verifier has already accepted as got.
func (v *Verifier) Verify(r *http.Request, got *httpsig.Verified[*cert.Cert]) error {
	vals := r.Header.Values(Header)
	switch len(vals) {
	case 0:
		return &Error{Reason: ReasonMissing}
	case 1:
	default:
		return fail(ReasonMalformed, "%d %s header fields, want 1", len(vals), Header)
	}
	a, err := Parse(vals[0])
	if err != nil {
		return &Error{Reason: ReasonMalformed, Err: err}
	}
	return v.Check(a, got.Base, got.Cert)
}

// Check verifies a against the signature base of the request it came with
// and the passkeys in c. The signature is checked first, so the reasons after
// it (rp, flags, type, challenge, origin) are only reported for assertions the
// passkey really made.
func (v *Verifier) Check(a *Assertion, base []byte, c *cert.Cert) error {
	return v.CheckChallenge(a, Challenge(base), c.Passkeys)
}

// CheckChallenge verifies a against challenge and passkeys, in the same order
// as Check. The IdP uses it for sign-in, where the challenge is random and the
// passkeys come from its configuration.
func (v *Verifier) CheckChallenge(a *Assertion, challenge []byte, passkeys []cert.Passkey) error {
	ad := a.AuthenticatorData
	if len(ad) < authDataLen {
		return fail(ReasonMalformed, "authenticatorData is %d bytes", len(ad))
	}
	i := slices.IndexFunc(passkeys, func(p cert.Passkey) bool { return bytes.Equal(p.ID, a.CredentialID) })
	if i < 0 {
		return fail(ReasonCredential, "credential %s isn't one of %d passkeys",
			base64.RawURLEncoding.EncodeToString(a.CredentialID), len(passkeys))
	}
	p := passkeys[i]
	cd := sha256.Sum256(a.ClientDataJSON)
	signed := sha256.Sum256(append(slices.Clip(ad), cd[:]...))
	if !ecdsa.VerifyASN1(p.Key, signed[:], a.Signature) {
		return &Error{Reason: ReasonSigMismatch}
	}
	if !bytes.Equal(ad[:32], v.rpIDHash[:]) {
		return fail(ReasonRP, "rpIdHash %x", ad[:32])
	}
	switch flags := ad[32]; {
	case flags&(flagAT|flagED) != 0:
		return fail(ReasonFlags, "flags %#02x: attested credential data or extensions", flags)
	case flags&flagUP == 0:
		return fail(ReasonFlags, "flags %#02x: user not present", flags)
	case flags&flagUV == 0:
		return fail(ReasonFlags, "flags %#02x: user not verified", flags)
	}
	if len(ad) != authDataLen {
		return fail(ReasonMalformed, "authenticatorData is %d bytes", len(ad))
	}
	return v.CheckClientData(a.ClientDataJSON, "webauthn.get", challenge)
}

// CheckClientData follows WebAuthn's limited verification algorithm
// (§5.8.1.2): browsers serialize type, challenge and origin first and in that
// order, so those are compared as bytes and no JSON parser decides what they
// are. The rest is parsed only to refuse crossOrigin and topOrigin. typ is
// webauthn.get for an assertion, webauthn.create for a registration.
func (v *Verifier) CheckClientData(cd []byte, typ string, challenge []byte) error {
	rest, ok := bytes.CutPrefix(cd, []byte(`{"type":"`))
	if !ok {
		return fail(ReasonMalformed, "clientDataJSON doesn't start with type")
	}
	if rest, ok = bytes.CutPrefix(rest, []byte(typ+`"`)); !ok {
		return fail(ReasonType, "clientDataJSON %.40q", cd)
	}
	want := `,"challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) + `","origin":"`
	if rest, ok = bytes.CutPrefix(rest, []byte(want)); !ok {
		return fail(ReasonChallenge, "clientDataJSON %.120q", cd)
	}
	if rest, ok = bytes.CutPrefix(rest, []byte(v.origin+`"`)); !ok || len(rest) == 0 || (rest[0] != '}' && rest[0] != ',') {
		return fail(ReasonOrigin, "clientDataJSON %q", cd)
	}
	var more struct {
		CrossOrigin bool    `json:"crossOrigin"`
		TopOrigin   *string `json:"topOrigin"`
	}
	if err := json.Unmarshal(cd, &more); err != nil {
		return &Error{Reason: ReasonMalformed, Err: fmt.Errorf("clientDataJSON: %w", err)}
	}
	if more.CrossOrigin || more.TopOrigin != nil {
		return fail(ReasonOrigin, "clientDataJSON %q: cross-origin", cd)
	}
	return nil
}
