// Package config reads the IdP's configuration: the JSON file the Nix module
// writes, and the CA key systemd passes in with LoadCredential.
//
// Everything is checked when it's loaded, so a mistake in the Nix
// configuration stops the IdP from starting (or, through sso config check,
// the deploy from building) rather than showing up at the first sign-in.
package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"net/url"
	"os"
	"slices"

	"github.com/oxgen1/sso/lib/assertion"
	"github.com/oxgen1/sso/lib/cert"
)

// Config is the checked configuration.
type Config struct {
	RPID          string
	Origin        string
	Listen        netip.AddrPort
	CACertificate []byte // DER
	Users         map[string]*User
	Clients       map[string]Client
	RetentionDays int

	// owners maps each passkey credential ID to its user.
	owners map[string]*User
}

// User is a user from the configuration.
type User struct {
	// Claims is what each certificate issued to the user says, with every
	// enrolled passkey.
	Claims   cert.Claims
	Passkeys []Passkey
}

// Passkey is an enrolled passkey and the name it was given at enrollment.
type Passkey struct {
	Name string
	cert.Passkey
}

// Client is a web app that signs in through sso-proxy.
type Client struct {
	RedirectURI string
}

// file is the JSON the Nix module writes, option for option.
type file struct {
	RPID          string                `json:"rpId"`
	Origin        string                `json:"origin"`
	ListenAddress string                `json:"listenAddress"`
	CACertificate string                `json:"caCertificate"` // path to the PEM
	Users         map[string]fileUser   `json:"users"`
	Clients       map[string]fileClient `json:"clients"`
	Audit         struct {
		RetentionDays int `json:"retentionDays"`
	} `json:"audit"`
}

type fileUser struct {
	Roles    []string      `json:"roles"`
	Services []string      `json:"services"`
	Sources  []string      `json:"sources"`
	Passkeys []filePasskey `json:"passkeys"`
}

type filePasskey struct {
	Name      string `json:"name"`
	ID        string `json:"id"`        // base64url, unpadded, as WebAuthn gives it
	PublicKey string `json:"publicKey"` // SubjectPublicKeyInfo, std base64
}

type fileClient struct {
	RedirectURI string `json:"redirectUri"`
}

// Load reads and checks the configuration at path.
func Load(path string) (*Config, error) {
	f, err := os.Open(path) // #nosec G304 -- the path is the operator's
	if err != nil {
		return nil, err
	}
	defer f.Close()
	c, err := parse(f, os.ReadFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// parse decodes and checks a configuration; readFile reads the CA
// certificate it names.
func parse(r io.Reader, readFile func(string) ([]byte, error)) (*Config, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var f file
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the configuration")
	}

	if _, err := assertion.NewVerifier(f.RPID, f.Origin); err != nil {
		return nil, err
	}
	c := &Config{
		RPID:          f.RPID,
		Origin:        f.Origin,
		Users:         make(map[string]*User, len(f.Users)),
		Clients:       make(map[string]Client, len(f.Clients)),
		RetentionDays: f.Audit.RetentionDays,
		owners:        make(map[string]*User),
	}
	var err error
	if c.Listen, err = netip.ParseAddrPort(f.ListenAddress); err != nil {
		return nil, fmt.Errorf("listenAddress: %w", err)
	}
	if c.RetentionDays < 1 {
		return nil, errors.New("audit.retentionDays must be at least 1")
	}
	pemBytes, err := readFile(f.CACertificate)
	if err != nil {
		return nil, fmt.Errorf("caCertificate: %w", err)
	}
	if c.CACertificate, err = decodePEM(pemBytes, "CERTIFICATE"); err != nil {
		return nil, fmt.Errorf("caCertificate: %w", err)
	}
	// The verifier refuses a certificate that isn't a usable CA.
	if _, err := cert.NewVerifier(c.CACertificate, "sso"); err != nil {
		return nil, fmt.Errorf("caCertificate: %w", err)
	}

	if len(f.Users) == 0 {
		return nil, errors.New("no users")
	}
	// Sorted, so the first error is the same every time.
	for _, name := range slices.Sorted(maps.Keys(f.Users)) {
		u, err := c.user(name, f.Users[name])
		if err != nil {
			return nil, fmt.Errorf("users.%s: %w", name, err)
		}
		c.Users[name] = u
	}
	for _, name := range slices.Sorted(maps.Keys(f.Clients)) {
		if err := checkRedirect(f.Clients[name].RedirectURI); err != nil {
			return nil, fmt.Errorf("clients.%s: %w", name, err)
		}
		if !cert.ValidName(name) {
			return nil, fmt.Errorf("clients.%s: not a valid service name", name)
		}
		c.Clients[name] = Client(f.Clients[name])
	}
	return c, nil
}

func (c *Config) user(name string, f fileUser) (*User, error) {
	u := &User{Claims: cert.Claims{User: name, Services: f.Services}}
	if len(f.Roles) > 0 {
		u.Claims.Roles = slices.Sorted(slices.Values(f.Roles))
	}
	for _, s := range f.Sources {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("sources: %w", err)
		}
		if p.Masked() != p {
			return nil, fmt.Errorf("sources: %s has host bits set; did you mean %s?", s, p.Masked())
		}
		u.Claims.Sources = append(u.Claims.Sources, p)
	}
	for i, fp := range f.Passkeys {
		p, err := decodePasskey(fp)
		if err != nil {
			return nil, fmt.Errorf("passkeys[%d]: %w", i, err)
		}
		if slices.ContainsFunc(u.Passkeys, func(q Passkey) bool { return q.Name == p.Name }) {
			return nil, fmt.Errorf("passkeys[%d]: name %q repeated", i, p.Name)
		}
		// Sign-in looks the user up by credential ID, so an ID can't belong
		// to two users.
		if other, ok := c.owners[string(p.ID)]; ok {
			return nil, fmt.Errorf("passkeys[%d]: credential ID already enrolled for %s", i, other.Claims.User)
		}
		c.owners[string(p.ID)] = u
		u.Passkeys = append(u.Passkeys, p)
		u.Claims.Passkeys = append(u.Claims.Passkeys, p.Passkey)
	}
	// Check catches bad names, repeated roles and services, and anything
	// else Issue would refuse later.
	if err := u.Claims.Check(); err != nil {
		return nil, err
	}
	return u, nil
}

func decodePasskey(f filePasskey) (Passkey, error) {
	if !cert.ValidName(f.Name) {
		return Passkey{}, fmt.Errorf("name %q: a lowercase letter, then lowercase letters, digits or hyphens", f.Name)
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(f.ID)
	if err != nil {
		return Passkey{}, fmt.Errorf("id: %w", err)
	}
	der, err := base64.StdEncoding.Strict().DecodeString(f.PublicKey)
	if err != nil {
		return Passkey{}, fmt.Errorf("publicKey: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return Passkey{}, fmt.Errorf("publicKey: %w", err)
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return Passkey{}, errors.New("publicKey isn't P-256")
	}
	return Passkey{Name: f.Name, Passkey: cert.Passkey{ID: id, Key: key}}, nil
}

// checkRedirect allows an https URL with a path and nothing else, so the
// IdP can compare it as a string.
func checkRedirect(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("redirectUri: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery || u.String() != s {
		return fmt.Errorf("redirectUri %q: want https://host/path with no query or fragment", s)
	}
	return nil
}

// PasskeyOwner returns the user a credential ID is enrolled for.
func (c *Config) PasskeyOwner(id []byte) (*User, Passkey, bool) {
	u, ok := c.owners[string(id)]
	if !ok {
		return nil, Passkey{}, false
	}
	i := slices.IndexFunc(u.Passkeys, func(p Passkey) bool { return bytes.Equal(p.ID, id) })
	return u, u.Passkeys[i], true
}

// LoadCA reads the CA key at keyFile, a PKCS #8 PEM as sso ca init writes it,
// and pairs it with the configured certificate.
func (c *Config) LoadCA(keyFile string) (*cert.CA, error) {
	pemBytes, err := os.ReadFile(keyFile) // #nosec G304 -- the path is the operator's
	if err != nil {
		return nil, err
	}
	ca, err := c.parseCA(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", keyFile, err)
	}
	return ca, nil
}

func (c *Config) parseCA(pemBytes []byte) (*cert.CA, error) {
	der, err := decodePEM(pemBytes, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA key")
	}
	return cert.NewCAFromDER(c.CACertificate, key)
}

// decodePEM returns the one block in b, which must be of type typ.
func decodePEM(b []byte, typ string) ([]byte, error) {
	block, rest := pem.Decode(b)
	if block == nil || block.Type != typ {
		return nil, fmt.Errorf("want one PEM block of type %s", typ)
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("data after the PEM block")
	}
	return block.Bytes, nil
}
