package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// NewCA makes a self-signed CA certificate for key, valid until notAfter.
// Rotating the CA (docs/design.md) means making a new one and deploying its
// certificate to every service.
func NewCA(name string, key *ecdsa.PrivateKey, now, notAfter time.Time) ([]byte, error) {
	if key.Curve != elliptic.P256() {
		return nil, errors.New("cert: CA key isn't P-256")
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-Backdate),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
}

// CA issues client certificates.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	Now  func() time.Time
}

// NewCAFromDER pairs a CA certificate (from NewCA) with its key.
func NewCAFromDER(der []byte, key *ecdsa.PrivateKey) (*CA, error) {
	ca, err := parseCA(der)
	if err != nil {
		return nil, err
	}
	if !key.PublicKey.Equal(ca.PublicKey) {
		return nil, errors.New("cert: key doesn't match the CA certificate")
	}
	return &CA{Cert: ca, Key: key}, nil
}

// Issue makes a certificate for the client key pub, valid for Lifetime from
// now. It parses its own output with the verifier's profile check, so the
// IdP can't hand out a certificate that services would reject.
func (ca *CA) Issue(pub *ecdsa.PublicKey, c Claims) ([]byte, *Cert, error) {
	tmpl, err := ca.template(pub, c)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := Parse(der)
	if err != nil {
		return nil, nil, fmt.Errorf("cert: issued certificate fails the profile: %w", err)
	}
	return der, parsed, nil
}

func (ca *CA) template(pub *ecdsa.PublicKey, c Claims) (*x509.Certificate, error) {
	if err := c.Check(); err != nil {
		return nil, fmt.Errorf("cert: %w", err)
	}
	if pub.Curve != elliptic.P256() {
		return nil, errors.New("cert: client key isn't P-256")
	}
	san, err := encodeServices(c.Services)
	if err != nil {
		return nil, err
	}
	exts := []pkix.Extension{{Id: oidSAN, Value: san}}
	for _, e := range []struct {
		id       asn1.ObjectIdentifier
		critical bool
		present  bool
		encode   func() ([]byte, error)
	}{
		{oidRoles, false, c.Roles != nil, func() ([]byte, error) { return encodeRoles(c.Roles) }},
		{oidPasskeys, false, c.Passkeys != nil, func() ([]byte, error) { return encodePasskeys(c.Passkeys) }},
		{oidSources, true, c.Sources != nil, func() ([]byte, error) { return encodeSources(c.Sources) }},
	} {
		if !e.present {
			continue
		}
		v, err := e.encode()
		if err != nil {
			return nil, err
		}
		exts = append(exts, pkix.Extension{Id: e.id, Critical: e.critical, Value: v})
	}

	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if ca.Now != nil {
		now = ca.Now()
	}
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: c.User},
		NotBefore:             now.Add(-Backdate),
		NotAfter:              now.Add(Lifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       exts,
	}, nil
}

// newSerial returns a random positive 128-bit serial whose top byte isn't
// zero, so it's always 32 hex digits as a keyid.
func newSerial() (*big.Int, error) {
	b := make([]byte, serialLen)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	b[0] = b[0]&0x7f | 0x40
	return new(big.Int).SetBytes(b), nil
}

func parseCA(der []byte) (*x509.Certificate, error) {
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("cert: CA: %w", err)
	}
	key, ok := ca.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() || !ca.IsCA || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("cert: not a P-256 CA certificate")
	}
	return ca, nil
}
