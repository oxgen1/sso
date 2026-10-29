// Package webauthn checks passkey registrations for sso enroll.
//
// Sign-in and approvals are assertions, which lib/assertion checks with the
// standard library alone. Registration is the one place CBOR appears: the
// attestation object and the COSE key inside it. Only what the enrollment
// page asks for is accepted: attestation "none", an ES256 key and user
// verification. The page asks for no extensions, but extension outputs it
// didn't ask for are ignored, as WebAuthn allows: a security key reports
// credProtect, which the browser requests for discoverable passkeys.
package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/oxgen1/sso/lib/assertion"
	"github.com/oxgen1/sso/lib/cert"
)

// authenticatorData flags (WebAuthn §6.1).
const (
	flagUP = 1 << 0
	flagUV = 1 << 2
	flagAT = 1 << 6
	flagED = 1 << 7
)

// rpIdHash, flags, signCount, then the attested credential data: AAGUID and
// the credential ID's length.
const (
	authDataHead  = 32 + 1 + 4
	attestedHead  = 16 + 2
	maxCredential = 1023
)

// COSE (RFC 9052 and 9053) labels and values for an ES256 P-256 key.
const (
	coseKtyEC2   = 2
	coseAlgES256 = -7
	coseCrvP256  = 1
)

// decMode refuses anything an authenticator has no reason to send:
// duplicate map keys, indefinite lengths, tags, unknown fields, and deep or
// large structures.
var decMode = func() cbor.DecMode {
	dm, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		MaxNestedLevels:   4,
		MaxArrayElements:  16,
		MaxMapPairs:       16,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return dm
}()

// RP checks registrations for one relying party.
type RP struct {
	verifier *assertion.Verifier
	rpIDHash [32]byte
}

// New returns an RP for rpID whose enrollment page is at origin, with the
// same rules as assertion.NewVerifier.
func New(rpID, origin string) (*RP, error) {
	v, err := assertion.NewVerifier(rpID, origin)
	if err != nil {
		return nil, err
	}
	return &RP{verifier: v, rpIDHash: sha256.Sum256([]byte(rpID))}, nil
}

type attestationObject struct {
	Fmt      string                     `cbor:"fmt"`
	AttStmt  map[string]cbor.RawMessage `cbor:"attStmt"`
	AuthData []byte                     `cbor:"authData"`
}

type coseKey struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

// Register checks the response to navigator.credentials.create made with
// challenge and returns the new passkey. With attestation "none" nothing is
// signed: what ties the key to this enrollment is the challenge, which only
// the holder of the enrollment link was given.
func (rp *RP) Register(attObj, clientDataJSON, challenge []byte) (cert.Passkey, error) {
	if err := rp.verifier.CheckClientData(clientDataJSON, "webauthn.create", challenge); err != nil {
		return cert.Passkey{}, err
	}
	var obj attestationObject
	if err := decMode.Unmarshal(attObj, &obj); err != nil {
		return cert.Passkey{}, fmt.Errorf("attestationObject: %w", err)
	}
	if obj.Fmt != "none" || len(obj.AttStmt) != 0 {
		return cert.Passkey{}, fmt.Errorf("attestation format %q, want none", obj.Fmt)
	}
	return rp.parseAuthData(obj.AuthData)
}

func (rp *RP) parseAuthData(ad []byte) (cert.Passkey, error) {
	if len(ad) < authDataHead+attestedHead {
		return cert.Passkey{}, fmt.Errorf("authenticatorData is %d bytes", len(ad))
	}
	if !bytes.Equal(ad[:32], rp.rpIDHash[:]) {
		return cert.Passkey{}, errors.New("rpIdHash isn't this RP's")
	}
	flags := ad[32]
	switch {
	case flags&flagUP == 0, flags&flagUV == 0:
		return cert.Passkey{}, fmt.Errorf("flags %#02x: user not present or not verified", flags)
	case flags&flagAT == 0:
		return cert.Passkey{}, fmt.Errorf("flags %#02x: no attested credential data", flags)
	}
	rest := ad[authDataHead+16:] // the AAGUID says which model; we don't ask
	n := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if n == 0 || n > maxCredential || n > len(rest) {
		return cert.Passkey{}, fmt.Errorf("credential ID length %d", n)
	}
	id := bytes.Clone(rest[:n])
	var k coseKey
	rest, err := decMode.UnmarshalFirst(rest[n:], &k)
	if err != nil {
		return cert.Passkey{}, fmt.Errorf("credential public key: %w", err)
	}
	if flags&flagED != 0 {
		// Ignored, but it has to be one well-formed map of extension outputs.
		var ext map[string]cbor.RawMessage
		if rest, err = decMode.UnmarshalFirst(rest, &ext); err != nil {
			return cert.Passkey{}, fmt.Errorf("flags %#02x: extensions: %w", flags, err)
		}
	}
	if len(rest) > 0 {
		return cert.Passkey{}, fmt.Errorf("%d bytes after the credential public key and extensions", len(rest))
	}
	key, err := k.ecdsa()
	if err != nil {
		return cert.Passkey{}, err
	}
	return cert.Passkey{ID: id, Key: key}, nil
}

func (k coseKey) ecdsa() (*ecdsa.PublicKey, error) {
	if k.Kty != coseKtyEC2 || k.Alg != coseAlgES256 || k.Crv != coseCrvP256 {
		return nil, fmt.Errorf("credential public key is kty %d alg %d crv %d, want ES256 on P-256", k.Kty, k.Alg, k.Crv)
	}
	if len(k.X) != 32 || len(k.Y) != 32 {
		return nil, errors.New("credential public key coordinates aren't 32 bytes")
	}
	point := append(append([]byte{4}, k.X...), k.Y...)
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("credential public key: %w", err)
	}
	return key, nil
}
