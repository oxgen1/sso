package main

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/oxgen1/sso/internal/config"
)

// configCheck loads a configuration without the CA key, so the Nix module
// can run it at build time and a bad configuration never deploys.
func configCheck(args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("config check: need one FILE")
	}
	c, err := config.Load(args[0])
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "rp %s, origin %s, listen %s\n", c.RPID, c.Origin, c.Listen)
	for _, name := range slices.Sorted(maps.Keys(c.Users)) {
		u := c.Users[name]
		fmt.Fprintf(out, "user %s: services %s; roles %s; %d passkeys\n", name,
			strings.Join(u.Claims.Services, ","), orNone(u.Claims.Roles), len(u.Passkeys))
	}
	for _, name := range slices.Sorted(maps.Keys(c.Clients)) {
		fmt.Fprintf(out, "client %s: %s\n", name, c.Clients[name].RedirectURI)
	}
	return nil
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ",")
}
