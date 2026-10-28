package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/oxgen1/sso/lib/cert"
)

// caInit makes a CA: ca.pem for the Nix configuration of the IdP and every
// service, and ca.key for the secrets tool.
func caInit(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("ca init", flag.ContinueOnError)
	name := fs.String("name", "", "CA common name")
	years := fs.Int("years", 5, "years until the CA expires")
	dir := fs.String("out", "", "directory to write ca.pem and ca.key to")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *dir == "" || *years < 1 || fs.NArg() > 0 {
		return errors.New("ca init: need --name, --out and a positive --years")
	}
	now := time.Now()
	if err := writeCA(*dir, *name, now, now.AddDate(*years, 0, 0)); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s: public, goes in the Nix configuration\n%s: private, goes in your secrets tool\n",
		filepath.Join(*dir, "ca.pem"), filepath.Join(*dir, "ca.key"))
	return nil
}

func writeCA(dir, name string, now, notAfter time.Time) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := cert.NewCA(name, key, now, notAfter)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// The key first: if it can't be written, there's no orphan certificate.
	if err := writeNew(filepath.Join(dir, "ca.key"), "PRIVATE KEY", keyDER, 0o600); err != nil {
		return err
	}
	return writeNew(filepath.Join(dir, "ca.pem"), "CERTIFICATE", der, 0o644)
}

// writeNew writes one PEM block to a file that mustn't already exist, so an
// existing CA is never overwritten.
func writeNew(path, typ string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304 -- the path is the operator's
	if err != nil {
		return err
	}
	err = pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
	return errors.Join(err, f.Close())
}
