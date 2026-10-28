package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/oxgen1/sso/lib/httpsig"
)

// Verifier checks client certificates for one service. Its Verify method is
// the Cert func of an httpsig.Verifier[*cert.Cert].
type Verifier struct {
	ca      *x509.Certificate
	service string
	// Addr returns the client address for the source check. The default is
	// the address in r.RemoteAddr, which is right for a service clients
	// connect to directly.
	Addr func(r *http.Request) (netip.Addr, error)
	Now  func() time.Time
}

// NewVerifier makes a Verifier for service, trusting only the CA certificate
// caDER.
func NewVerifier(caDER []byte, service string) (*Verifier, error) {
	if !validName(service) {
		return nil, fmt.Errorf("cert: invalid service name %q", service)
	}
	ca, err := parseCA(caDER)
	if err != nil {
		return nil, err
	}
	return &Verifier{ca: ca, service: service}, nil
}

// Verify checks der against the CA, the profile, keyID, the validity period,
// this service and the client address, in that order. The signature comes
// before the time and scope checks so that cert_expired and scope are only
// ever reported for certificates the CA really issued. Errors are
// *httpsig.Error with ReasonCert, ReasonCertExpired or ReasonScope.
func (v *Verifier) Verify(r *http.Request, der []byte, keyID string) (*ecdsa.PublicKey, *Cert, error) {
	x, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, failCert(err)
	}
	// CheckSignatureFrom rather than x509.Verify: with one root and no
	// intermediates there's no path to build, and the profile check below
	// covers key usage and extensions more strictly than Verify does.
	if !bytes.Equal(x.RawIssuer, v.ca.RawSubject) {
		return nil, nil, failCert(errors.New("issuer isn't the CA"))
	}
	if err := x.CheckSignatureFrom(v.ca); err != nil {
		return nil, nil, failCert(err)
	}
	c, err := fromX509(x)
	if err != nil {
		return nil, nil, failCert(err)
	}
	if keyID != c.Serial {
		return nil, nil, failCert(fmt.Errorf("keyid %q, serial %s", keyID, c.Serial))
	}

	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	switch {
	case now.After(v.ca.NotAfter) || now.Before(v.ca.NotBefore):
		return nil, nil, failCert(fmt.Errorf("CA valid %v to %v", v.ca.NotBefore, v.ca.NotAfter))
	case now.After(c.NotAfter):
		return nil, nil, &httpsig.Error{Reason: httpsig.ReasonCertExpired, Err: fmt.Errorf("expired %v", c.NotAfter)}
	case now.Before(c.NotBefore):
		return nil, nil, failCert(fmt.Errorf("not valid before %v", c.NotBefore))
	}

	if !slices.Contains(c.Services, v.service) {
		return nil, nil, failScope(fmt.Errorf("services %v, not %s", c.Services, v.service))
	}
	if len(c.Sources) > 0 {
		addr, err := v.addr(r)
		if err != nil {
			return nil, nil, failScope(err)
		}
		if !slices.ContainsFunc(c.Sources, func(p netip.Prefix) bool { return p.Contains(addr) }) {
			return nil, nil, failScope(fmt.Errorf("address %v not in %v", addr, c.Sources))
		}
	}
	return c.Key, c, nil
}

func (v *Verifier) addr(r *http.Request) (netip.Addr, error) {
	if v.Addr != nil {
		a, err := v.Addr(r)
		return a.Unmap(), err
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("remote address: %w", err)
	}
	return ap.Addr().Unmap(), nil
}

func failCert(err error) *httpsig.Error {
	return &httpsig.Error{Reason: httpsig.ReasonCert, Err: err}
}

func failScope(err error) *httpsig.Error {
	return &httpsig.Error{Reason: httpsig.ReasonScope, Err: err}
}
