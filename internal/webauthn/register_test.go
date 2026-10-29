package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/oxgen1/sso/lib/assertion"
	"github.com/oxgen1/sso/lib/cert"
)

const (
	testRPID   = "auth.jack.farm"
	testOrigin = "https://id.auth.jack.farm"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// WebAuthn Level 3 §16.2, "ES256 Credential with No Attestation".
var (
	specRegChallenge = unhex("00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130")
	specPrivateKey   = unhex("6e68e7a58484a3264f66b77f5d6dc5bc36a47085b615c9727ab334e8c369c2ee")
	specCredentialID = unhex("f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4")
	specRegClient    = unhex("7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d")
	specAttObj       = unhex("a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220")
	specGetChallenge = unhex("39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408")
	specGetAuthData  = unhex("bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000")
	specGetClient    = unhex("7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d")
	specSignature    = unhex("3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87")
)

func TestSpecVector(t *testing.T) {
	rp, err := New("example.org", "https://example.org")
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), specPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	// The vector's authenticator didn't verify the user (flags 0x59), and the
	// enrollment page requires it.
	if _, err := rp.Register(specAttObj, specRegClient, specRegChallenge); err == nil || !strings.Contains(err.Error(), "not verified") {
		t.Fatalf("as published: %v, want user not verified", err)
	}
	// Nothing signs a registration with attestation none, so setting UV
	// leaves a valid response to check the parse against.
	// The rpIdHash is the same in both ceremonies; the flags follow it.
	attObj := bytes.Clone(specAttObj)
	at := bytes.Index(attObj, specGetAuthData[:32]) + 32
	if at < 32 || attObj[at] != 0x59 {
		t.Fatalf("flags not found")
	}
	attObj[at] |= flagUV
	p, err := rp.Register(attObj, specRegClient, specRegChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.ID, specCredentialID) || !p.Key.Equal(&priv.PublicKey) {
		t.Errorf("got ID %x key %v, want %x and the key of credential_private_key", p.ID, p.Key, specCredentialID)
	}

	// The authentication is signed, so its UV bit stays clear: it must pass
	// the signature and rpIdHash and stop at the flags.
	v, err := assertion.NewVerifier("example.org", "https://example.org")
	if err != nil {
		t.Fatal(err)
	}
	a := &assertion.Assertion{CredentialID: p.ID, AuthenticatorData: specGetAuthData, ClientDataJSON: specGetClient, Signature: specSignature}
	if err := v.CheckChallenge(a, specGetChallenge, []cert.Passkey{p}); assertion.ReasonOf(err) != assertion.ReasonFlags {
		t.Errorf("authentication: %v, want %s", err, assertion.ReasonFlags)
	}
}

// registration is what a software authenticator and the browser send back,
// in parts so a test can change any of them.
type registration struct {
	rpID      string
	flags     byte
	credID    []byte
	idLen     int // the length written before credID, when not 0
	key       map[int]any
	adTail    []byte
	fmt       string
	attStmt   map[string]any
	extra     map[string]any // more top-level members of the attestation object
	typ       string
	challenge []byte
	origin    string
	raw       []byte // replaces the attestation object when set
}

type authenticator struct {
	id  []byte
	key *ecdsa.PrivateKey
}

func newAuthenticator(t testing.TB) authenticator {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	rand.Read(id)
	return authenticator{id: id, key: k}
}

var testChallenge = bytes.Repeat([]byte{7}, 32)

func (a authenticator) registration() registration {
	point, err := a.key.PublicKey.Bytes()
	if err != nil {
		panic(err)
	}
	return registration{
		rpID:   testRPID,
		flags:  flagUP | flagUV | flagAT,
		credID: a.id,
		key: map[int]any{
			1: coseKtyEC2, 3: coseAlgES256, -1: coseCrvP256,
			-2: point[1:33], -3: point[33:],
		},
		fmt:       "none",
		attStmt:   map[string]any{},
		typ:       "webauthn.create",
		challenge: testChallenge,
		origin:    testOrigin,
	}
}

var encMode = func() cbor.EncMode {
	em, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return em
}()

func (r registration) encode(t testing.TB) (attObj, clientData []byte) {
	t.Helper()
	clientData = fmt.Appendf(nil, `{"type":%q,"challenge":"%s","origin":%q,"crossOrigin":false}`,
		r.typ, b64url(r.challenge), r.origin)
	if r.raw != nil {
		return r.raw, clientData
	}
	rp := sha256.Sum256([]byte(r.rpID))
	ad := append(rp[:], r.flags, 0, 0, 0, 0)
	ad = append(ad, make([]byte, 16)...) // AAGUID
	n := len(r.credID)
	if r.idLen != 0 {
		n = r.idLen
	}
	ad = binary.BigEndian.AppendUint16(ad, uint16(n)) // #nosec G115 -- tests write lengths up to 1024
	ad = append(ad, r.credID...)
	key, err := encMode.Marshal(r.key)
	if err != nil {
		t.Fatal(err)
	}
	ad = append(append(ad, key...), r.adTail...)
	obj := map[string]any{"fmt": r.fmt, "attStmt": r.attStmt, "authData": ad}
	for k, v := range r.extra {
		obj[k] = v
	}
	attObj, err = encMode.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return attObj, clientData
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newRP(t testing.TB) *RP {
	t.Helper()
	rp, err := New(testRPID, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

func TestRegister(t *testing.T) {
	rp := newRP(t)
	auth := newAuthenticator(t)
	attObj, cd := auth.registration().encode(t)
	p, err := rp.Register(attObj, cd, testChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.ID, auth.id) || !p.Key.Equal(&auth.key.PublicKey) {
		t.Fatalf("got %x %v", p.ID, p.Key)
	}

	// A security key's unrequested credProtect output (flags 0xc5) is
	// ignored.
	r := auth.registration()
	r.flags |= flagED
	r.adTail = credProtect
	attObj, cd = r.encode(t)
	if p, err := rp.Register(attObj, cd, testChallenge); err != nil || !p.Key.Equal(&auth.key.PublicKey) {
		t.Errorf("with credProtect (flags %#x): %v", r.flags, err)
	}

	// The passkey signs in through lib/assertion, as the IdP will use it.
	v, err := assertion.NewVerifier(testRPID, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	challenge := bytes.Repeat([]byte{9}, 32)
	rpHash := sha256.Sum256([]byte(testRPID))
	ad := append(rpHash[:], flagUP|flagUV, 0, 0, 0, 1)
	getCD := fmt.Appendf(nil, `{"type":"webauthn.get","challenge":"%s","origin":%q}`, b64url(challenge), testOrigin)
	h := sha256.Sum256(getCD)
	signed := sha256.Sum256(append(bytes.Clone(ad), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, auth.key, signed[:])
	if err != nil {
		t.Fatal(err)
	}
	a := &assertion.Assertion{CredentialID: p.ID, AuthenticatorData: ad, ClientDataJSON: getCD, Signature: sig}
	if err := v.CheckChallenge(a, challenge, []cert.Passkey{p}); err != nil {
		t.Errorf("sign-in with the registered passkey: %v", err)
	}
}

// credProtect is the extension output a security key such as a YubiKey adds
// to a discoverable passkey, as {"credProtect": 2}.
var credProtect = unhex("a16b6372656450726f7465637402")

type mutation struct {
	name   string
	change func(*registration)
	want   string
}

func mutations(t testing.TB) []mutation {
	other := newAuthenticator(t)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384Point, err := p384.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return []mutation{
		{"type get", func(r *registration) { r.typ = "webauthn.get" }, "assertion_type"},
		{"other challenge", func(r *registration) { r.challenge = []byte{1} }, "assertion_challenge"},
		{"other origin", func(r *registration) { r.origin = "https://evil.auth.jack.farm" }, "assertion_origin"},
		{"other RP", func(r *registration) { r.rpID = "jack.farm" }, "rpIdHash"},
		{"no UP", func(r *registration) { r.flags &^= flagUP }, "not present"},
		{"no UV", func(r *registration) { r.flags &^= flagUV }, "not verified"},
		{"no AT", func(r *registration) { r.flags &^= flagAT }, "no attested"},
		{"ED without extensions", func(r *registration) { r.flags |= flagED }, "extensions"},
		{"extensions not a map", func(r *registration) { r.flags |= flagED; r.adTail = []byte{0x02} }, "extensions"},
		{"extensions with an integer key", func(r *registration) { r.flags |= flagED; r.adTail = unhex("a10102") }, "extensions"},
		{"extensions without ED", func(r *registration) { r.adTail = credProtect }, "14 bytes after"},
		{"bytes after extensions", func(r *registration) {
			r.flags |= flagED
			r.adTail = append(bytes.Clone(credProtect), 0)
		}, "1 bytes after"},
		{"empty credential ID", func(r *registration) { r.credID = nil }, "credential ID length 0"},
		{"long credential ID", func(r *registration) { r.credID = make([]byte, 1024) }, "credential ID length 1024"},
		{"credential ID past end", func(r *registration) { r.idLen = 1000 }, "credential ID length 1000"},
		{"credential ID short", func(r *registration) { r.idLen = len(r.credID) - 1 }, "credential public key"},
		{"packed", func(r *registration) { r.fmt = "packed" }, `"packed"`},
		{"attStmt", func(r *registration) { r.attStmt = map[string]any{"alg": -7} }, "want none"},
		{"extra member", func(r *registration) { r.extra = map[string]any{"epAtt": true} }, "unknown field"},
		{"RS256", func(r *registration) { r.key[3] = -257 }, "alg -257"},
		{"OKP", func(r *registration) { r.key[1] = 1 }, "kty 1"},
		{"P-384", func(r *registration) {
			r.key[-1] = 2
			r.key[-2], r.key[-3] = p384Point[1:49], p384Point[49:]
		}, "crv 2"},
		{"P-384 point as P-256", func(r *registration) { r.key[-2], r.key[-3] = p384Point[1:49], p384Point[49:] }, "32 bytes"},
		{"not on curve", func(r *registration) { r.key[-3] = bytes.Repeat([]byte{1}, 32) }, "credential public key"},
		{"x from another key", func(r *registration) {
			pt, _ := other.key.PublicKey.Bytes()
			r.key[-2] = pt[1:33]
		}, "credential public key"},
		{"kid", func(r *registration) { r.key[2] = []byte("kid") }, "unknown field"},
		{"no key", func(r *registration) { r.key = map[int]any{} }, "kty 0"},
		{"kty as text", func(r *registration) { r.key[1] = "EC2" }, "credential public key"},
		{"not CBOR", func(r *registration) { r.raw = []byte{0xff} }, "attestationObject"},
		{"trailing CBOR", func(r *registration) {
			attObj, _ := r.encode(t)
			r.raw = append(attObj, 0)
		}, "attestationObject"},
		{"duplicate key", func(r *registration) {
			// {"fmt": "none", "fmt": "none"}
			r.raw = unhex("a263666d74646e6f6e6563666d74646e6f6e65")
		}, "duplicate"},
		{"indefinite map", func(r *registration) { r.raw = unhex("bf63666d74646e6f6e65ff") }, "indefinite"},
		{"tag", func(r *registration) { r.raw = unhex("d818a0") }, "tag"},
	}
}

func TestRegisterRejects(t *testing.T) {
	rp := newRP(t)
	auth := newAuthenticator(t)
	for _, m := range mutations(t) {
		t.Run(m.name, func(t *testing.T) {
			r := auth.registration()
			m.change(&r)
			attObj, cd := r.encode(t)
			_, err := rp.Register(attObj, cd, testChallenge)
			if err == nil || !strings.Contains(err.Error(), m.want) {
				t.Errorf("err = %v, want it to mention %q", err, m.want)
			}
		})
	}
}

// FuzzParseAuthData checks that whatever authenticatorData is accepted has
// the shape the enrollment page asks for, and that the key it returns is the
// one in the data.
func FuzzParseAuthData(f *testing.F) {
	auth := newAuthenticator(f)
	for _, m := range mutations(f) {
		r := auth.registration()
		m.change(&r)
		attObj, _ := r.encode(f)
		var obj attestationObject
		if decMode.Unmarshal(attObj, &obj) == nil {
			f.Add(obj.AuthData)
		}
	}
	rp := newRP(f)
	rpHash := sha256.Sum256([]byte(testRPID))
	f.Fuzz(func(t *testing.T, ad []byte) {
		p, err := rp.parseAuthData(ad)
		if err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(ad[authDataHead+16:]))
		switch {
		case !bytes.Equal(ad[:32], rpHash[:]):
			t.Fatal("accepted another RP")
		case ad[32]&(flagUP|flagUV|flagAT) != flagUP|flagUV|flagAT:
			t.Fatalf("accepted flags %#x", ad[32])
		case !bytes.Equal(p.ID, ad[authDataHead+attestedHead:][:n]):
			t.Fatal("ID isn't the one in the data")
		case p.Key.Curve != elliptic.P256():
			t.Fatal("not P-256")
		}
	})
}
