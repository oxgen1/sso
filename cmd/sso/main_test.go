package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

	cfg := filepath.Join(t.TempDir(), "sso.json")
	json := `{"rpId":"auth.jack.farm","origin":"https://id.auth.jack.farm","listenAddress":"127.0.0.1:9300",
		"caCertificate":"` + filepath.Join(dir, "ca.pem") + `",
		"users":{"jack":{"roles":["write"],"services":["statusd"],"sources":[],"passkeys":[]}},
		"clients":{},"audit":{"retentionDays":90}}`
	if err := os.WriteFile(cfg, []byte(json), 0o600); err != nil {
		t.Fatal(err)
	}
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
	for _, args := range [][]string{nil, {"ca"}, {"serve"}, {"ca", "init"}, {"ca", "init", "--out", "x"}, {"config", "check"}} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%q: no error", args)
		}
	}
}
