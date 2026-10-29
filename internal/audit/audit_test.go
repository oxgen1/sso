package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 28, 9, 0, 0, 0, time.FixedZone("CET", 3600))

func now() time.Time { return t0 }

// run writes a chain of n events between audit_start and audit_stop, and
// returns its lines.
func run(t *testing.T, n int) []string {
	t.Helper()
	var b bytes.Buffer
	l, err := New(&b, now)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if err := l.Write("login", "allow", "", "user", "jack", "i", i); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
}

func verify(t *testing.T, lines ...string) Report {
	t.Helper()
	rep, err := Verify(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestWrite(t *testing.T) {
	var b bytes.Buffer
	l, err := New(&b, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Write("certificate", "deny", "device_code", "user_code", "BCDF-GHJK", "n", 3, "html", "<&>"); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
	zero := strings.Repeat("0", 64)
	if want := `{"log":"audit","v":1,"seq":0,"prev":"` + zero + `","server_time":"2026-10-28T08:00:00Z","action":"audit_start"}`; lines[0] != want {
		t.Errorf("start\n%s, want\n%s", lines[0], want)
	}
	h := sha256.Sum256([]byte(lines[0]))
	html, _ := json.Marshal("<&>") // escaped as \u003c and so on
	want := `{"log":"audit","v":1,"seq":1,"prev":"` + hex.EncodeToString(h[:]) +
		`","server_time":"2026-10-28T08:00:00Z","action":"certificate","result":"deny","reason":"device_code",` +
		`"user_code":"BCDF-GHJK","n":3,"html":` + string(html) + `}`
	if lines[1] != want {
		t.Errorf("event\n%s, want\n%s", lines[1], want)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &m); err != nil || m["html"] != "<&>" {
		t.Errorf("not JSON: %v %v", err, m)
	}

	for name, attrs := range map[string][]any{
		"odd":        {"user"},
		"key":        {1, "x"},
		"unencoding": {"f", func() {}},
	} {
		if err := l.Write("login", "allow", "", attrs...); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// A refused record doesn't use up a seq.
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if rep := verify(t, strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")...); len(rep.Problems) != 0 {
		t.Errorf("problems: %v", rep.Problems)
	}
}

type failWriter struct{ n int }

func (w *failWriter) Write(p []byte) (int, error) {
	if w.n--; w.n < 0 {
		return 0, errors.New("disk full")
	}
	return len(p), nil
}

func TestWriteFails(t *testing.T) {
	if _, err := New(&failWriter{}, now); err == nil {
		t.Error("New: no error")
	}
	l, err := New(&failWriter{n: 1}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Write("login", "allow", ""); err == nil {
		t.Error("Write: no error")
	}
	// The lost record still advanced the chain, so the gap shows.
	if l.seq != 2 {
		t.Errorf("seq %d", l.seq)
	}
}

func TestVerify(t *testing.T) {
	a, b := run(t, 3), run(t, 2)
	rep := verify(t, append(append([]string{"not json", `{"log":"diag","msg":"request"}`}, a...), b...)...)
	if len(rep.Problems) != 0 {
		t.Fatalf("problems: %v", rep.Problems)
	}
	want := []Chain{
		{FirstLine: 3, LastLine: 7, FirstSeq: 0, LastSeq: 4, Started: true, Stopped: true},
		{FirstLine: 8, LastLine: 11, FirstSeq: 0, LastSeq: 3, Started: true, Stopped: true},
	}
	if rep.Records != 9 || rep.Skipped != 2 || len(rep.Chains) != 2 || rep.Chains[0] != want[0] || rep.Chains[1] != want[1] {
		t.Errorf("report %+v", rep)
	}

	// Rotation took the oldest records; the IdP is still running.
	rep = verify(t, a[2:4]...)
	if len(rep.Problems) != 0 || len(rep.Chains) != 1 ||
		rep.Chains[0] != (Chain{FirstLine: 1, LastLine: 2, FirstSeq: 2, LastSeq: 3}) {
		t.Errorf("rotated: %+v", rep)
	}
	// A crash: the next run starts without the last one stopping.
	rep = verify(t, append(a[:3:3], b...)...)
	if len(rep.Problems) != 0 || len(rep.Chains) != 2 || rep.Chains[0].Stopped || !rep.Chains[1].Stopped {
		t.Errorf("crash: %+v", rep)
	}
}

func TestVerifyFinds(t *testing.T) {
	a, b := run(t, 3), run(t, 1)
	edit := func(i int, from, to string) []string {
		out := append([]string(nil), a...)
		out[i] = strings.Replace(out[i], from, to, 1)
		return out
	}
	without := func(lines []string, i int) []string {
		return append(append([]string(nil), lines[:i]...), lines[i+1:]...)
	}
	for name, tc := range map[string]struct {
		lines []string
		line  int
		msg   string
	}{
		"edited":         {edit(2, `"jack"`, `"eve"`), 4, "prev doesn't match line 3"},
		"deleted":        {without(a, 2), 3, "seq 3 follows seq 1"},
		"swapped":        {[]string{a[0], a[2], a[1], a[3]}, 2, "seq 2 follows seq 0"},
		"start cut":      {append(a[:5:5], without(b, 0)...), 6, "seq 1 starts a chain without audit_start"},
		"forged start":   {append(a[:2:2], strings.Replace(a[2], `"login"`, `"audit_start"`, 1)), 3, "audit_start with seq 2"},
		"after stop":     {append(a[:5:5], a[2]), 6, "seq 2 starts a chain without audit_start"},
		"no seq":         {[]string{a[0], `{"log":"audit","v":1,"prev":"00"}`}, 2, "not a version 1 audit record"},
		"other version":  {edit(1, `"v":1`, `"v":2`), 2, "not a version 1 audit record"},
		"short prev":     {edit(1, `"prev":"`, `"prev":"a`), 2, "not a version 1 audit record"},
		"edited, no gap": {edit(1, `"i":0`, `"i":9`), 3, "prev doesn't match line 2"},
	} {
		rep := verify(t, tc.lines...)
		if len(rep.Problems) == 0 || rep.Problems[0].Line != tc.line || !strings.HasPrefix(rep.Problems[0].Msg, tc.msg) {
			t.Errorf("%s: %+v", name, rep.Problems)
		}
	}
}

func TestVerifyLongLine(t *testing.T) {
	if _, err := Verify(strings.NewReader(strings.Repeat("x", maxLine+1))); err == nil {
		t.Error("no error for a line over the limit")
	}
}
