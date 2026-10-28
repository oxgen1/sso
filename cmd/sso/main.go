// sso is the IdP and CA: passkey sign-in, the device flow, client
// certificates and destructive-action approval (docs/design.md).
//
//	sso ca init --name NAME [--years N] --out DIR
//	sso config check FILE
package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const usage = `usage:
  sso ca init --name NAME [--years N] --out DIR
  sso config check FILE
`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "sso:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	cmd := strings.Join(args[:min(2, len(args))], " ")
	switch cmd {
	case "ca init":
		return caInit(args[2:], out)
	case "config check":
		return configCheck(args[2:], out)
	}
	return fmt.Errorf("unknown command %q\n%s", cmd, usage)
}
