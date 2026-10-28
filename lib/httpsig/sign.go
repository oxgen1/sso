package httpsig

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

// Signer signs requests with a client key and the certificate the IdP issued
// for it.
type Signer struct {
	Key   *ecdsa.PrivateKey
	Cert  []byte // DER, sent in the Sso-Cert header
	KeyID string // the certificate serial
	Now   func() time.Time
}

// Sign sets Content-Digest, Sso-Cert, Signature-Input and Signature on r.
// body must be what will be sent as r's body. It returns the signature base,
// so a caller can print BaseHash when a request is rejected.
func (s *Signer) Sign(r *http.Request, body []byte) ([]byte, error) {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	created := now().Unix()
	return s.sign(r, body, Label, components, Params{
		Created: created,
		Expires: created + int64(lifetime/time.Second),
		Nonce:   base64.RawURLEncoding.EncodeToString(nonce),
		KeyID:   s.KeyID,
		Tag:     Tag,
	}.list())
}

// sign is Sign with the label, components and parameters given, so tests can
// make validly signed requests that are outside the profile.
func (s *Signer) sign(r *http.Request, body []byte, label string, items []string, params []param) ([]byte, error) {
	for _, p := range params {
		if !p.isNum && !validString(p.str) {
			return nil, errors.New("httpsig: parameter " + p.key + " can't be serialized")
		}
	}
	r.Header.Set(HeaderContentDigest, ContentDigest(body))
	r.Header.Set(HeaderCert, serializeBytes(s.Cert))
	in := sigInput{label: label, items: items, params: params}
	sigParams := in.value()
	base, err := signatureBase(func(name string) (string, error) {
		return requestValue(r, name)
	}, items, sigParams)
	if err != nil {
		return nil, err
	}
	sig, err := signES256(s.Key, base)
	if err != nil {
		return nil, err
	}
	r.Header.Set(HeaderSignatureInput, label+"="+sigParams)
	r.Header.Set(HeaderSignature, label+"="+serializeBytes(sig))
	return base, nil
}
