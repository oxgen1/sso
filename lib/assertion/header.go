package assertion

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Header carries the assertion, as an RFC 8941 dictionary in the same
// canonical subset httpsig accepts: these four members in this order, each a
// padded byte sequence, separated by ", ".
//
//	Sso-Assertion: id=:<base64>:, ad=:<base64>:, cd=:<base64>:, sig=:<base64>:
//
// The request signature doesn't cover it and can't: the assertion is over the
// signature base, so it only exists once the request is signed. Nothing is
// lost, since an assertion is only good for the one base it was made over.
const Header = "Sso-Assertion"

// maxHeader is several times what an assertion with the longest credential ID
// takes.
const maxHeader = 8 << 10

// WebAuthn credential IDs are at most 1023 bytes, as in cert.
const maxCredentialID = 1023

// Assertion is the response of a WebAuthn get. The user handle is left out:
// the credential ID alone picks the key from the certificate, and the
// certificate already names the user.
type Assertion struct {
	CredentialID      []byte
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte // ASN.1 DER, as WebAuthn returns it
}

var members = []string{"id", "ad", "cd", "sig"}

func (a *Assertion) fields() [][]byte {
	return [][]byte{a.CredentialID, a.AuthenticatorData, a.ClientDataJSON, a.Signature}
}

// Value serializes a for the Sso-Assertion header.
func (a *Assertion) Value() string {
	parts := make([]string, len(members))
	for i, b := range a.fields() {
		parts[i] = members[i] + "=:" + base64.StdEncoding.EncodeToString(b) + ":"
	}
	return strings.Join(parts, ", ")
}

// Parse parses an Sso-Assertion header value. Only the form Value produces is
// accepted, so whatever parses serializes back to exactly the input.
func Parse(s string) (*Assertion, error) {
	if len(s) > maxHeader {
		return nil, fmt.Errorf("%d bytes, limit %d", len(s), maxHeader)
	}
	parts := strings.Split(s, ", ")
	if len(parts) != len(members) {
		return nil, fmt.Errorf("%d members, want %d", len(parts), len(members))
	}
	var a Assertion
	out := []*[]byte{&a.CredentialID, &a.AuthenticatorData, &a.ClientDataJSON, &a.Signature}
	for i, p := range parts {
		b64, prefix := strings.CutPrefix(p, members[i]+"=:")
		b64, suffix := strings.CutSuffix(b64, ":")
		if !prefix || !suffix {
			return nil, fmt.Errorf("member %d isn't the byte sequence %s", i, members[i])
		}
		b, err := base64.StdEncoding.Strict().DecodeString(b64)
		// Go's decoder skips CR and LF; re-encoding rules those out.
		if err != nil || base64.StdEncoding.EncodeToString(b) != b64 {
			return nil, fmt.Errorf("%s: not canonical base64", members[i])
		}
		if len(b) == 0 {
			return nil, fmt.Errorf("%s: empty", members[i])
		}
		*out[i] = b
	}
	if len(a.CredentialID) > maxCredentialID {
		return nil, errors.New("credential ID too long")
	}
	return &a, nil
}
