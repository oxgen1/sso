package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

const (
	// Lifetime is how long a certificate lasts: a working day. There's no
	// revocation, so this is how long a stolen key stays useful.
	Lifetime = 8 * time.Hour
	// Backdate is how far NotBefore is set before issuance, so a service whose
	// clock is a little behind the IdP's still accepts a new certificate.
	Backdate = 5 * time.Minute
	// ServicePrefix starts each service URI SAN; the service name follows.
	ServicePrefix = "https://id.auth.jack.farm/services/"
	serialLen     = 16
)

// Claims is what a certificate says about its holder.
type Claims struct {
	User     string
	Services []string
	Roles    []string       // sorted
	Passkeys []Passkey      // for the destructive tier
	Sources  []netip.Prefix // empty means any address
}

// Cert is a parsed certificate that matches the profile.
type Cert struct {
	Claims
	// Serial is the certificate serial as 32 lowercase hex digits, the keyid
	// of every request signed with it.
	Serial    string
	Key       *ecdsa.PublicKey
	NotBefore time.Time
	NotAfter  time.Time
}

// HasRole reports whether the certificate grants role.
func (c *Cert) HasRole(role string) bool {
	_, found := slices.BinarySearch(c.Roles, role)
	return found
}

// Passkey returns the passkey with this credential ID.
func (c *Cert) Passkey(id []byte) (Passkey, bool) {
	i := slices.IndexFunc(c.Passkeys, func(p Passkey) bool { return string(p.ID) == string(id) })
	if i < 0 {
		return Passkey{}, false
	}
	return c.Passkeys[i], true
}

func (c Claims) check() error {
	if !validName(c.User) {
		return errors.New("invalid user name")
	}
	if len(c.Services) == 0 {
		return errors.New("no services")
	}
	for i, s := range c.Services {
		if !validName(s) || slices.Contains(c.Services[:i], s) {
			return fmt.Errorf("service %q invalid or repeated", s)
		}
	}
	if c.Roles != nil {
		if err := checkRoles(c.Roles); err != nil {
			return err
		}
	}
	if c.Passkeys != nil {
		if err := checkPasskeys(c.Passkeys); err != nil {
			return err
		}
	}
	if c.Sources != nil {
		if err := checkSources(c.Sources); err != nil {
			return err
		}
	}
	return nil
}

// Standard extensions a certificate must carry, besides the private ones.
var (
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidSAN              = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidAuthorityKeyID   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidCommonName       = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// Parse parses a certificate and checks that it matches the profile. It
// doesn't check the signature, validity period or scope: that's Verifier.
func Parse(der []byte) (*Cert, error) {
	x, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c, err := fromX509(x)
	if err != nil {
		return nil, fmt.Errorf("cert: %w", err)
	}
	return c, nil
}

func fromX509(x *x509.Certificate) (*Cert, error) {
	if x.Version != 3 || x.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return nil, fmt.Errorf("version %d, algorithm %v", x.Version, x.SignatureAlgorithm)
	}
	key, ok := x.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("key isn't P-256")
	}
	serial := x.SerialNumber.Bytes()
	if x.SerialNumber.Sign() <= 0 || len(serial) != serialLen {
		return nil, errors.New("serial isn't 128 bits")
	}
	if len(x.Subject.Names) != 1 || !x.Subject.Names[0].Type.Equal(oidCommonName) {
		return nil, errors.New("subject isn't a lone CN")
	}
	if x.KeyUsage != x509.KeyUsageDigitalSignature ||
		!slices.Equal(x.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) ||
		len(x.UnknownExtKeyUsage) > 0 {
		return nil, errors.New("key usage isn't digitalSignature and clientAuth")
	}
	if !x.BasicConstraintsValid || x.IsCA {
		return nil, errors.New("basic constraints")
	}
	if d := x.NotAfter.Sub(x.NotBefore); d <= 0 || d > Lifetime+Backdate {
		return nil, fmt.Errorf("lifetime %v", d)
	}

	c := &Cert{
		Claims:    Claims{User: x.Subject.CommonName},
		Serial:    hex.EncodeToString(serial),
		Key:       key,
		NotBefore: x.NotBefore,
		NotAfter:  x.NotAfter,
	}
	var err error
	required := []asn1.ObjectIdentifier{oidKeyUsage, oidExtKeyUsage, oidBasicConstraints, oidSAN, oidAuthorityKeyID}
	for _, ext := range x.Extensions {
		if i := slices.IndexFunc(required, ext.Id.Equal); i >= 0 {
			required = slices.Delete(required, i, i+1)
			if ext.Id.Equal(oidSAN) {
				if c.Services, err = decodeServices(ext.Value); err != nil {
					return nil, fmt.Errorf("SAN: %w", err)
				}
			}
			continue
		}
		if err := c.decodeExtension(ext); err != nil {
			return nil, fmt.Errorf("extension %v: %w", ext.Id, err)
		}
	}
	if len(required) > 0 {
		return nil, fmt.Errorf("missing extension %v", required[0])
	}
	if err := c.check(); err != nil {
		return nil, err
	}
	return c, nil
}

// decodeExtension decodes one of the private extensions. Each has a fixed
// criticality: only sources is critical, because a verifier that ignored it
// would accept the certificate from anywhere. Ignoring roles or passkeys only
// grants less. (crypto/x509 rejects a repeated extension while parsing.)
func (c *Cert) decodeExtension(ext pkix.Extension) error {
	var err error
	switch {
	case ext.Id.Equal(oidRoles) && !ext.Critical:
		c.Roles, err = decodeRoles(ext.Value)
	case ext.Id.Equal(oidPasskeys) && !ext.Critical:
		c.Passkeys, err = decodePasskeys(ext.Value)
	case ext.Id.Equal(oidSources) && ext.Critical:
		c.Sources, err = decodeSources(ext.Value)
	default:
		err = errors.New("not in the profile")
	}
	return err
}

// The SAN holds only URIs, one per service. crypto/x509 skips name forms it
// doesn't know, so the extension is rebuilt from the services and compared.
func encodeServices(services []string) ([]byte, error) {
	names := make([]asn1.RawValue, len(services))
	for i, s := range services {
		names[i] = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(ServicePrefix + s)}
	}
	return asn1.Marshal(names)
}

func decodeServices(der []byte) ([]string, error) {
	var names []asn1.RawValue
	if err := unmarshal(der, &names); err != nil {
		return nil, err
	}
	services := make([]string, len(names))
	for i, n := range names {
		s, ok := strings.CutPrefix(string(n.Bytes), ServicePrefix)
		if n.Class != asn1.ClassContextSpecific || n.Tag != 6 || !ok {
			return nil, errors.New("not a service URI")
		}
		services[i] = s
	}
	return services, recheck(der, services, encodeServices)
}
