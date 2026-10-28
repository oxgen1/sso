package cert

// This file encodes and decodes the three private extensions:
//
//	roles     SEQUENCE OF PrintableString, sorted, no duplicates
//	passkeys  SEQUENCE OF SEQUENCE { credentialID OCTET STRING,
//	                                  publicKey SubjectPublicKeyInfo }
//	sources   SEQUENCE OF OCTET STRING, each address || mask, as the
//	          iPAddress form of RFC 5280 name constraints
//
// None of them may be empty: an absent extension is the only way to say
// "none". Decoding re-encodes the result and compares it to the input, so each
// value has exactly one accepted encoding, as in the httpsig parser.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/bits"
	"net/netip"
	"slices"
)

// oidArc is the private arc for the extensions.
//
// TODO: replace with an IANA Private Enterprise Number arc
// (1.3.6.1.4.1.<PEN>) before tagging lib/v0.1.0. The design's 2.25.<uuid> arc
// can't be used: crypto/x509 parses extension OIDs into []int and rejects any
// arc of 2^31 or more, so a certificate carrying one doesn't parse at all.
// 2.999 is the arc ITU-T reserves for examples.
var oidArc = asn1.ObjectIdentifier{2, 999, 7}

var (
	oidRoles    = append(slices.Clone(oidArc), 1)
	oidPasskeys = append(slices.Clone(oidArc), 2)
	oidSources  = append(slices.Clone(oidArc), 3)
)

var errEncoding = errors.New("not the canonical DER encoding")

// Passkey is a passkey public key the user registered: its WebAuthn
// credential ID and the key, converted from COSE by the IdP.
type Passkey struct {
	ID  []byte
	Key *ecdsa.PublicKey
}

// WebAuthn credential IDs are at most 1023 bytes.
const maxCredentialID = 1023

type passkeyASN1 struct {
	ID  []byte
	Key asn1.RawValue
}

func encodeRoles(roles []string) ([]byte, error) {
	return asn1.Marshal(roles)
}

func decodeRoles(der []byte) ([]string, error) {
	var roles []string
	if err := unmarshal(der, &roles); err != nil {
		return nil, err
	}
	if err := checkRoles(roles); err != nil {
		return nil, err
	}
	return roles, recheck(der, roles, encodeRoles)
}

func checkRoles(roles []string) error {
	if len(roles) == 0 {
		return errors.New("empty role list")
	}
	for i, r := range roles {
		if !ValidName(r) {
			return errors.New("invalid role name")
		}
		if i > 0 && roles[i-1] >= r {
			return errors.New("roles not sorted or repeated")
		}
	}
	return nil
}

func encodePasskeys(keys []Passkey) ([]byte, error) {
	out := make([]passkeyASN1, len(keys))
	for i, k := range keys {
		spki, err := x509.MarshalPKIXPublicKey(k.Key)
		if err != nil {
			return nil, err
		}
		out[i] = passkeyASN1{ID: k.ID, Key: asn1.RawValue{FullBytes: spki}}
	}
	return asn1.Marshal(out)
}

func decodePasskeys(der []byte) ([]Passkey, error) {
	var raw []passkeyASN1
	if err := unmarshal(der, &raw); err != nil {
		return nil, err
	}
	keys := make([]Passkey, len(raw))
	for i, r := range raw {
		pub, err := x509.ParsePKIXPublicKey(r.Key.FullBytes)
		if err != nil {
			return nil, err
		}
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("passkey key isn't ECDSA")
		}
		keys[i] = Passkey{ID: r.ID, Key: key}
	}
	if err := checkPasskeys(keys); err != nil {
		return nil, err
	}
	return keys, recheck(der, keys, encodePasskeys)
}

func checkPasskeys(keys []Passkey) error {
	if len(keys) == 0 {
		return errors.New("empty passkey list")
	}
	for i, k := range keys {
		if len(k.ID) == 0 || len(k.ID) > maxCredentialID {
			return errors.New("passkey credential ID length")
		}
		if k.Key == nil || k.Key.Curve != elliptic.P256() {
			return errors.New("passkey key isn't P-256")
		}
		for _, prev := range keys[:i] {
			if bytes.Equal(prev.ID, k.ID) {
				return errors.New("passkey credential ID repeated")
			}
		}
	}
	return nil
}

func encodeSources(prefixes []netip.Prefix) ([]byte, error) {
	out := make([][]byte, len(prefixes))
	for i, p := range prefixes {
		addr := p.Addr().AsSlice()
		mask := make([]byte, len(addr))
		for b := range p.Bits() {
			mask[b/8] |= 0x80 >> (b % 8)
		}
		out[i] = append(addr, mask...)
	}
	return asn1.Marshal(out)
}

func decodeSources(der []byte) ([]netip.Prefix, error) {
	var raw [][]byte
	if err := unmarshal(der, &raw); err != nil {
		return nil, err
	}
	prefixes := make([]netip.Prefix, len(raw))
	for i, r := range raw {
		if len(r) != 8 && len(r) != 32 {
			return nil, errors.New("source length")
		}
		addr, _ := netip.AddrFromSlice(r[:len(r)/2])
		mask := r[len(r)/2:]
		n := 0
		for _, m := range mask {
			n += bits.OnesCount8(m)
		}
		p := netip.PrefixFrom(addr, n)
		if p.Masked() != p {
			return nil, errors.New("source address has bits outside its mask")
		}
		prefixes[i] = p
	}
	if err := checkSources(prefixes); err != nil {
		return nil, err
	}
	// A non-contiguous mask has the same bit count as a contiguous one, so
	// the re-encoding comparison is what rejects it.
	return prefixes, recheck(der, prefixes, encodeSources)
}

func checkSources(prefixes []netip.Prefix) error {
	if len(prefixes) == 0 {
		return errors.New("empty source list")
	}
	for _, p := range prefixes {
		if !p.IsValid() || p.Addr().Is4In6() || p.Addr().Zone() != "" || p.Masked() != p {
			return errors.New("invalid source prefix")
		}
	}
	return nil
}

// unmarshal decodes der into v with nothing left over.
func unmarshal(der []byte, v any) error {
	rest, err := asn1.Unmarshal(der, v)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return errors.New("trailing data")
	}
	return nil
}

// recheck re-encodes v and compares it to der.
func recheck[T any](der []byte, v T, encode func(T) ([]byte, error)) error {
	again, err := encode(v)
	if err != nil || !bytes.Equal(again, der) {
		return errEncoding
	}
	return nil
}

// ValidName reports whether s is a user, role or service name: a lowercase
// letter, then up to 31 lowercase letters, digits or hyphens.
func ValidName(s string) bool {
	if len(s) == 0 || len(s) > 32 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}
