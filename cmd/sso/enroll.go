package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/oxgen1/sso/internal/config"
	"github.com/oxgen1/sso/internal/idp"
)

// enroll prints a one-time link for a user to register a passkey. It needs
// the CA key, as the link is MACed with a key derived from it.
func enroll(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	keyFile := fs.String("ca-key", "", "CA key (default $CREDENTIALS_DIRECTORY/ca.key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("enroll: need FILE and USER")
	}
	cfg, err := config.Load(fs.Arg(0))
	if err != nil {
		return err
	}
	ca, err := loadCA(cfg, *keyFile)
	if err != nil {
		return err
	}
	link, exp, err := idp.EnrollLink(cfg, ca, fs.Arg(1), time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Enrollment link for %s, for one passkey, until %s:\n  %s\n",
		fs.Arg(1), exp.Format("15:04 MST"), link)
	return nil
}
