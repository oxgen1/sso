package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

// Chain is one run of the IdP, as found in a log.
type Chain struct {
	FirstLine, LastLine int
	FirstSeq, LastSeq   uint64
	// Started is whether the chain's audit_start was in the log. Only the
	// first chain may lack it, where older records have been rotated away.
	Started bool
	// Stopped is whether it ended with audit_stop. If not, the IdP is still
	// running, crashed, or the chain's end was cut off.
	Stopped bool
}

// Problem is a place where the chain is broken.
type Problem struct {
	Line int
	Msg  string
}

// Report is what Verify found.
type Report struct {
	Records  int // audit records
	Skipped  int // other lines: diagnostic records, anything not JSON
	Chains   []Chain
	Problems []Problem
}

// maxLine is far more than any record; journald splits lines at 48 KiB.
const maxLine = 1 << 20

// Verify checks the audit records in r, as journalctl -o cat prints them,
// skipping every other line. The error is only for reading r.
func Verify(r io.Reader) (Report, error) {
	var (
		rep  Report
		cur  *Chain // nil between chains
		prev [sha256.Size]byte
		line int
	)
	problem := func(format string, a ...any) {
		rep.Problems = append(rep.Problems, Problem{line, fmt.Sprintf(format, a...)})
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(nil, maxLine)
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		var rec struct {
			Log    string  `json:"log"`
			V      int     `json:"v"`
			Seq    *uint64 `json:"seq"`
			Prev   string  `json:"prev"`
			Action string  `json:"action"`
		}
		if json.Unmarshal(raw, &rec) != nil || rec.Log != "audit" {
			rep.Skipped++
			continue
		}
		rep.Records++
		p, err := hex.DecodeString(rec.Prev)
		if rec.V != Version || rec.Seq == nil || err != nil || len(p) != sha256.Size {
			problem("not a version %d audit record with seq and prev", Version)
			cur = nil
			continue
		}
		seq := *rec.Seq

		switch {
		case rec.Action == actionStart:
			if seq != 0 || [sha256.Size]byte(p) != [sha256.Size]byte{} {
				problem("audit_start with seq %d or a nonzero prev", seq)
			}
			rep.Chains = append(rep.Chains, Chain{FirstLine: line, FirstSeq: seq, Started: true})
			cur = &rep.Chains[len(rep.Chains)-1]
		case cur == nil:
			// Rotation may have taken the start of the oldest chain, never
			// of a later one.
			if len(rep.Chains) > 0 {
				problem("seq %d starts a chain without audit_start: records are missing before it", seq)
			}
			rep.Chains = append(rep.Chains, Chain{FirstLine: line, FirstSeq: seq})
			cur = &rep.Chains[len(rep.Chains)-1]
		case seq != cur.LastSeq+1:
			problem("seq %d follows seq %d on line %d: records are missing or out of order", seq, cur.LastSeq, cur.LastLine)
		case [sha256.Size]byte(p) != prev:
			problem("prev doesn't match line %d: that record or this one was changed", cur.LastLine)
		}
		cur.LastLine, cur.LastSeq = line, seq
		prev = sha256.Sum256(raw)
		if rec.Action == actionStop {
			cur.Stopped = true
			cur = nil
		}
	}
	return rep, sc.Err()
}
