package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oxgen1/sso/internal/audit"
	"github.com/oxgen1/sso/internal/config"
)

func TestCAInitThenCheck(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	var out bytes.Buffer
	if err := run([]string{"ca", "init", "--name", "test CA", "--out", dir}, &out); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]os.FileMode{"ca.key": 0o600, "ca.pem": 0o644} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		// The umask can only take permissions away.
		if fi.Mode().Perm()&^want != 0 {
			t.Errorf("%s: mode %v, want at most %v", name, fi.Mode().Perm(), want)
		}
	}

	// A second init must not replace the CA.
	keyBefore, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"ca", "init", "--name", "again", "--out", dir}, &out); !errors.Is(err, os.ErrExist) {
		t.Errorf("second init: %v, want ErrExist", err)
	}
	if keyAfter, _ := os.ReadFile(filepath.Join(dir, "ca.key")); !bytes.Equal(keyBefore, keyAfter) {
		t.Error("second init changed ca.key")
	}

	cfg := writeConfig(t, filepath.Join(dir, "ca.pem"), "127.0.0.1:9300")
	out.Reset()
	if err := run([]string{"config", "check", cfg}, &out); err != nil {
		t.Fatal(err)
	}
	if want := "user jack: services statusd; roles write; 0 passkeys\n"; !strings.Contains(out.String(), want) {
		t.Errorf("output %q lacks %q", out.String(), want)
	}

	c, err := config.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.LoadCA(filepath.Join(dir, "ca.key")); err != nil {
		t.Errorf("the key ca init wrote doesn't load: %v", err)
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"ca"}, {"serve"}, {"serve", "/nonexistent"}, {"ca", "init"}, {"ca", "init", "--out", "x"}, {"config", "check"}} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%q: no error", args)
		}
	}
}

func writeConfig(t *testing.T, caPEM, listen string) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "sso.json")
	json := `{"rpId":"auth.jack.farm","origin":"https://id.auth.jack.farm","listenAddress":"` + listen + `",
		"caCertificate":"` + caPEM + `",
		"users":{"jack":{"roles":["write"],"services":["statusd"],"sources":[],"passkeys":[]}},
		"clients":{},"audit":{"retentionDays":90}}`
	if err := os.WriteFile(cfg, []byte(json), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestServe(t *testing.T) {
	dir := t.TempDir()
	if err := run([]string{"ca", "init", "--name", "test CA", "--out", dir}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	// A free port: there's a small window for something else to take it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	cfg := writeConfig(t, filepath.Join(dir, "ca.pem"), addr)

	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if err := serveUntil(context.Background(), []string{cfg}, &bytes.Buffer{}); err == nil {
		t.Error("no error without CREDENTIALS_DIRECTORY")
	}
	t.Setenv("CREDENTIALS_DIRECTORY", t.TempDir())
	if err := serveUntil(context.Background(), []string{cfg}, &bytes.Buffer{}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("no ca.key: %v", err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	var logs bytes.Buffer
	go func() { errc <- serveUntil(ctx, []string{cfg}, &logs) }()

	var resp *http.Response
	for range 50 {
		if resp, err = http.Get("http://" + addr + "/signin"); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /signin: %s", resp.Status)
	}
	cancel()
	if err := <-errc; err != nil {
		t.Errorf("shutdown: %v", err)
	}
	if !strings.Contains(logs.String(), `"msg":"listening"`) {
		t.Errorf("logs: %s", logs.String())
	}

	// The run left one whole chain, which audit verify reads from a file.
	file := filepath.Join(t.TempDir(), "journal")
	if err := os.WriteFile(file, logs.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"audit", "verify", file}, &out); err != nil {
		t.Fatalf("audit verify: %v\n%s", err, &out)
	}
	if !strings.Contains(out.String(), "2 audit records in 1 chains") || strings.Contains(out.String(), "no audit_stop") {
		t.Errorf("audit verify:\n%s", &out)
	}
}

func TestAuditVerify(t *testing.T) {
	var b bytes.Buffer
	l, err := audit.New(&b, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"jack", "guest"} {
		if err := l.Write("login", "allow", "", "user", u); err != nil {
			t.Fatal(err)
		}
	}
	good := b.String()
	var out bytes.Buffer
	if err := auditVerify([]string{"-"}, strings.NewReader(good), &out); err != nil ||
		out.String() != "3 audit records in 1 chains; 0 other lines skipped\n"+
			"  chain 1: lines 1-3, seq 0-2, no audit_stop (still running, crashed, or cut off)\n" {
		t.Errorf("good: %v\n%s", err, &out)
	}
	out.Reset()
	lines := strings.SplitAfter(good, "\n")
	if err := auditVerify([]string{"-"}, strings.NewReader(lines[2]), &out); err != nil ||
		!strings.Contains(out.String(), "seq 2-2, earlier records not given") {
		t.Errorf("rotated: %v\n%s", err, &out)
	}
	out.Reset()
	if err := auditVerify([]string{"-"}, strings.NewReader(strings.Replace(good, "jack", "eve", 1)), &out); err == nil ||
		!strings.Contains(out.String(), "line 3: prev doesn't match line 2") {
		t.Errorf("tampered: %v\n%s", err, &out)
	}
	for _, args := range [][]string{nil, {"a", "b"}, {"/nonexistent"}} {
		if err := auditVerify(args, strings.NewReader(""), &out); err == nil {
			t.Errorf("%q: no error", args)
		}
	}
	if err := auditVerify([]string{"-"}, strings.NewReader(strings.Repeat("x", 2<<20)), &out); err == nil {
		t.Error("overlong line: no error")
	}
}

func TestEnroll(t *testing.T) {
	dir := t.TempDir()
	if err := run([]string{"ca", "init", "--name", "test CA", "--out", dir}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	cfg := writeConfig(t, filepath.Join(dir, "ca.pem"), "127.0.0.1:9300")
	var out bytes.Buffer
	if err := run([]string{"enroll", "--ca-key", filepath.Join(dir, "ca.key"), cfg, "jack"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Enrollment link for jack") || !strings.Contains(out.String(), "  https://id.auth.jack.farm/enroll/jack.") {
		t.Errorf("output %q", out.String())
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if err := run([]string{"enroll", cfg, "jack"}, &bytes.Buffer{}); err != nil {
		t.Errorf("key from CREDENTIALS_DIRECTORY: %v", err)
	}
	for _, args := range [][]string{
		{"enroll", cfg, "root"},
		{"enroll", cfg},
		{"enroll", "--nope", cfg, "jack"},
		{"enroll", "/nonexistent", "jack"},
		{"enroll", "--ca-key", "/nonexistent", cfg, "jack"},
	} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%q: no error", args)
		}
	}
}
