package assertion

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"slices"
	"testing"
)

// FuzzParse checks that whatever parses serializes back to the input.
func FuzzParse(f *testing.F) {
	f.Add("id=:AQID:, ad=:BA==:, cd=:e30=:, sig=:BQY=:")
	f.Add("id=:AQID:, ad=:BA==:, cd=:e30=:")
	f.Fuzz(func(t *testing.T, s string) {
		a, err := Parse(s)
		if err != nil {
			return
		}
		if a.Value() != s {
			t.Fatalf("Parse(%q).Value() = %q", s, a.Value())
		}
	})
}

// FuzzCheck signs whatever authenticatorData and clientDataJSON it's given
// with the certificate's passkey, so the checks after the signature are
// reached, and checks that an accepted assertion has exactly the form the
// profile allows.
func FuzzCheck(f *testing.F) {
	auth := newAuthenticator(f)
	for _, m := range mutations(f) {
		r := auth.response(testBase)
		m.change(&r)
		a := r.sign(f)
		f.Add(a.AuthenticatorData, a.ClientDataJSON)
	}
	v := newVerifier(f)
	c := certFor(auth)
	prefix := []byte(`{"type":"webauthn.get","challenge":"`)
	rp := sha256.Sum256([]byte(testRPID))
	f.Fuzz(func(t *testing.T, ad, cd []byte) {
		h := sha256.Sum256(cd)
		signed := sha256.Sum256(append(slices.Clip(ad), h[:]...))
		sig, err := ecdsa.SignASN1(rand.Reader, auth.key, signed[:])
		if err != nil {
			t.Fatal(err)
		}
		err = v.Check(&Assertion{CredentialID: auth.id, AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig}, testBase, c)
		if err != nil {
			if ReasonOf(err) == "" || !slices.Contains(reasons, ReasonOf(err)) {
				t.Fatalf("unknown reason: %v", err)
			}
			return
		}
		switch {
		case len(ad) != authDataLen, !bytes.Equal(ad[:32], rp[:]), ad[32]&(flagUP|flagUV|flagAT|flagED) != flagUP|flagUV:
			t.Fatalf("accepted authenticatorData %x", ad)
		case !bytes.HasPrefix(cd, prefix), !bytes.Contains(cd, []byte(`","origin":"`+testOrigin+`"`)):
			t.Fatalf("accepted clientDataJSON %q", cd)
		}
	})
}
