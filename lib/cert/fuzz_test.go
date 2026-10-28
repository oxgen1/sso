package cert

import (
	"bytes"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/oxgen1/sso/lib/httpsig"
)

// FuzzExtensions checks that whatever the extension decoders accept encodes
// back to exactly the input, so each value has one accepted encoding.
func FuzzExtensions(f *testing.F) {
	c := testClaims(f)
	for _, seed := range []func() ([]byte, error){
		func() ([]byte, error) { return encodeRoles(c.Roles) },
		func() ([]byte, error) { return encodePasskeys(c.Passkeys) },
		func() ([]byte, error) { return encodeSources(c.Sources) },
		func() ([]byte, error) { return encodeServices(c.Services) },
	} {
		b, err := seed()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		if v, err := decodeRoles(der); err == nil {
			roundTrip(t, der, v, encodeRoles)
		}
		if v, err := decodePasskeys(der); err == nil {
			roundTrip(t, der, v, encodePasskeys)
		}
		if v, err := decodeSources(der); err == nil {
			roundTrip(t, der, v, encodeSources)
		}
		if v, err := decodeServices(der); err == nil {
			roundTrip(t, der, v, encodeServices)
		}
	})
}

func roundTrip[T any](t *testing.T, der []byte, v T, encode func(T) ([]byte, error)) {
	again, err := encode(v)
	if err != nil || !bytes.Equal(again, der) {
		t.Fatalf("%x decoded to %v, encodes to %x (%v)", der, v, again, err)
	}
}

// FuzzVerify feeds arbitrary DER to Parse and Verify. Neither may panic,
// Verify must fail only with a Cert reason, and anything Verify accepts must
// carry the CA's signature.
func FuzzVerify(f *testing.F) {
	fx := newFixture(f)
	fx.build()
	f.Add(fx.der, fx.keyID)
	f.Add([]byte{0x30, 0}, "")
	f.Fuzz(func(t *testing.T, der []byte, keyID string) {
		_, _ = Parse(der)
		r := httptest.NewRequest(http.MethodGet, "http://farm-1:9200/", nil)
		r.RemoteAddr = testRemote
		_, c, err := fx.v.Verify(r, der, keyID)
		if err != nil {
			if !slices.Contains([]httpsig.Reason{httpsig.ReasonCert, httpsig.ReasonCertExpired, httpsig.ReasonScope}, httpsig.ReasonOf(err)) {
				t.Fatalf("reason outside the Cert set: %v", err)
			}
			return
		}
		x, err := x509.ParseCertificate(der)
		if err != nil || x.CheckSignatureFrom(fx.ca.Cert) != nil || c.Serial != keyID {
			t.Fatalf("accepted a certificate the CA didn't sign for keyid %q", keyID)
		}
	})
}
