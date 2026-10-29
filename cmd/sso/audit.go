package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/oxgen1/sso/internal/audit"
)

// auditVerify checks the audit log's hash chains in FILE, or standard input
// for "-":
//
//	journalctl -u sso -o cat | sso audit verify -
func auditVerify(args []string, in io.Reader, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("audit verify: need FILE, or - for standard input")
	}
	if args[0] != "-" {
		f, err := os.Open(args[0]) // #nosec G304 G703 -- the path is the operator's
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}
	rep, err := audit.Verify(in)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%d audit records in %d chains; %d other lines skipped\n", rep.Records, len(rep.Chains), rep.Skipped)
	for i, c := range rep.Chains {
		var notes string
		if !c.Started {
			notes += ", earlier records not given"
		}
		if !c.Stopped {
			notes += ", no audit_stop (still running, crashed, or cut off)"
		}
		fmt.Fprintf(out, "  chain %d: lines %d-%d, seq %d-%d%s\n", i+1, c.FirstLine, c.LastLine, c.FirstSeq, c.LastSeq, notes)
	}
	for _, p := range rep.Problems {
		fmt.Fprintf(out, "line %d: %s\n", p.Line, p.Msg)
	}
	if n := len(rep.Problems); n > 0 {
		return fmt.Errorf("audit verify: %d problems", n)
	}
	return nil
}
