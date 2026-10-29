package idp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oxgen1/sso/internal/audit"
	"github.com/oxgen1/sso/internal/config"
	"github.com/oxgen1/sso/lib/cert"
)

const (
	rpID   = "auth.jack.farm"
	origin = "https://id.auth.jack.farm"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// authenticator is a software passkey.
type authenticator struct {
	id  []byte
	key *ecdsa.PrivateKey
}

func newAuthenticator(t *testing.T) *authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &authenticator{id: id, key: key}
}

func (a *authenticator) configJSON(t *testing.T, name string) string {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&a.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"name":%q,"id":%q,"publicKey":%q}`, name,
		base64.RawURLEncoding.EncodeToString(a.id), base64.StdEncoding.EncodeToString(spki))
}

// signOpts changes what the authenticator signs.
type signOpts struct {
	rpID     string
	flags    byte
	typ      string
	origin   string
	extra    string // appended inside clientDataJSON
	resign   bool   // sign with a different key
	credID   []byte
	sigBytes []byte
}

func (a *authenticator) sign(t *testing.T, challenge []byte, o signOpts) finishRequest {
	t.Helper()
	if o.rpID == "" {
		o.rpID = rpID
	}
	if o.typ == "" {
		o.typ = "webauthn.get"
	}
	if o.origin == "" {
		o.origin = origin
	}
	if o.credID == nil {
		o.credID = a.id
	}
	h := sha256.Sum256([]byte(o.rpID))
	ad := append(h[:], o.flags, 0, 0, 0, 0)
	cd := []byte(fmt.Sprintf(`{"type":%q,"challenge":%q,"origin":%q%s}`,
		o.typ, base64.RawURLEncoding.EncodeToString(challenge), o.origin, o.extra))
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(bytes.Clone(ad), cdHash[:]...))
	key := a.key
	if o.resign {
		key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if o.sigBytes != nil {
		sig = o.sigBytes
	}
	enc := base64.RawURLEncoding.EncodeToString
	return finishRequest{CredentialID: enc(o.credID), AuthenticatorData: enc(ad), ClientDataJSON: enc(cd), Signature: enc(sig)}
}

type env struct {
	t     *testing.T
	srv   *Server
	ca    *cert.CA
	clock *clock
	log   *logBuffer
	jack  *authenticator
	guest *authenticator
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	der, err := cert.NewCA("test CA", caKey, now, now.AddDate(1, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, clock: &clock{t: now}, log: &logBuffer{}, jack: newAuthenticator(t), guest: newAuthenticator(t)}
	cfgJSON := `{"rpId":"` + rpID + `","origin":"` + origin + `","listenAddress":"127.0.0.1:9300",
		"caCertificate":"` + caPath + `",
		"users":{
			"jack":{"roles":["write"],"services":["statusd"],"sources":[],"passkeys":[` + e.jack.configJSON(t, "yubikey") + `]},
			"guest":{"roles":[],"services":["grafana"],"sources":["192.168.1.0/24"],"passkeys":[` + e.guest.configJSON(t, "phone") + `]}},
		"clients":{},"audit":{"retentionDays":90}}`
	cfgPath := filepath.Join(dir, "sso.json")
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if e.ca, err = cert.NewCAFromDER(der, caKey); err != nil {
		t.Fatal(err)
	}
	e.ca.Now = e.clock.now
	aud, err := audit.New(e.log, e.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	e.srv, err = New(cfg, e.ca, slog.New(slog.NewJSONHandler(e.log, nil)), aud, e.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	// Whatever a test did, the audit records it left form one chain.
	t.Cleanup(func() {
		rep, err := audit.Verify(strings.NewReader(e.log.String()))
		if err != nil || len(rep.Problems) != 0 || len(rep.Chains) != 1 || !rep.Chains[0].Started {
			t.Errorf("audit chain: %v %+v", err, rep)
		}
	})
	return e
}

// logBuffer is where both logs go. Handlers run concurrently in some tests,
// and the two logs don't share a lock.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type req struct {
	method, path string
	body         any    // JSON-encoded unless a string
	origin       string // "-" for none
	cookie       string
	remote       string
	header       http.Header
}

func (e *env) do(r req) *httptest.ResponseRecorder {
	e.t.Helper()
	var body []byte
	switch b := r.body.(type) {
	case nil:
	case string:
		body = []byte(b)
	default:
		var err error
		if body, err = json.Marshal(b); err != nil {
			e.t.Fatal(err)
		}
	}
	hr := httptest.NewRequest(r.method, "https://id.auth.jack.farm"+r.path, bytes.NewReader(body))
	for k, v := range r.header {
		hr.Header[k] = v
	}
	if r.body != nil && hr.Header.Get("Content-Type") == "" {
		hr.Header.Set("Content-Type", "application/json")
	}
	switch r.origin {
	case "":
		if r.method == http.MethodPost {
			hr.Header.Set("Origin", origin)
		}
	case "-":
	default:
		hr.Header.Set("Origin", r.origin)
	}
	if r.cookie != "" {
		hr.AddCookie(&http.Cookie{Name: sessionCookie, Value: r.cookie})
	}
	hr.RemoteAddr = "10.0.0.5:40000"
	if r.remote != "" {
		hr.RemoteAddr = r.remote
	}
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, hr)
	return w
}

// begin returns the challenge ID and challenge.
func (e *env) begin() (string, []byte) {
	e.t.Helper()
	w := e.do(req{method: "POST", path: "/signin/begin", body: struct{}{}})
	if w.Code != http.StatusOK {
		e.t.Fatalf("begin: %d %s", w.Code, w.Body)
	}
	var b beginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		e.t.Fatal(err)
	}
	if b.RPID != rpID || b.Timeout != 120_000 {
		e.t.Errorf("begin: %+v", b)
	}
	ch, err := base64.RawURLEncoding.DecodeString(b.Challenge)
	if err != nil || len(ch) != 32 {
		e.t.Fatalf("challenge %q", b.Challenge)
	}
	return b.ID, ch
}

// signIn signs in with a and returns the session cookie.
func (e *env) signIn(a *authenticator) string {
	e.t.Helper()
	id, ch := e.begin()
	f := a.sign(e.t, ch, signOpts{flags: 0x05})
	f.ID = id
	w := e.do(req{method: "POST", path: "/signin/finish", body: f})
	if w.Code != http.StatusOK {
		e.t.Fatalf("finish: %d %s", w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" || c.MaxAge != 8*3600 {
				e.t.Errorf("cookie attributes: %+v", c)
			}
			return c.Value
		}
	}
	e.t.Fatal("finish set no session cookie")
	return ""
}

// audits returns the audit records logged so far.
func (e *env) audits() []map[string]any {
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(e.log.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			e.t.Fatalf("log line %q: %v", line, err)
		}
		if m["log"] == "audit" {
			out = append(out, m)
		}
	}
	return out
}

func (e *env) lastAudit() map[string]any {
	e.t.Helper()
	a := e.audits()
	if len(a) == 0 {
		e.t.Fatal("no audit record")
	}
	return a[len(a)-1]
}

func TestSignIn(t *testing.T) {
	e := newEnv(t)

	w := e.do(req{method: "GET", path: "/"})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/signin" {
		t.Fatalf("/ without a session: %d %q", w.Code, w.Header().Get("Location"))
	}
	w = e.do(req{method: "GET", path: "/signin?next=/device"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `data-next="/device"`) {
		t.Fatalf("/signin: %d %s", w.Code, w.Body)
	}

	cookie := e.signIn(e.jack)
	a := e.lastAudit()
	if a["action"] != "login" || a["result"] != "allow" || a["user"] != "jack" || a["passkey"] != "yubikey" ||
		a["client_ip"] != "10.0.0.5" || a["passkey_cred_id"] != base64.RawURLEncoding.EncodeToString(e.jack.id) ||
		a["server_time"] != "2026-10-28T09:00:00Z" || a["v"] != 1.0 || a["request_id"] == "" {
		t.Errorf("login audit record: %v", a)
	}

	w = e.do(req{method: "GET", path: "/", cookie: cookie})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Signed in as <strong>jack</strong> with yubikey") {
		t.Errorf("/ with a session: %d %s", w.Code, w.Body)
	}
	w = e.do(req{method: "GET", path: "/signin?next=/device", cookie: cookie})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/device" {
		t.Errorf("/signin with a session: %d %q", w.Code, w.Header().Get("Location"))
	}

	// A second sign-in in the same browser ends the first session.
	id, ch := e.begin()
	f := e.guest.sign(t, ch, signOpts{flags: 0x05})
	f.ID = id
	if w := e.do(req{method: "POST", path: "/signin/finish", body: f, cookie: cookie}); w.Code != http.StatusOK {
		t.Fatalf("second sign-in: %d", w.Code)
	}
	if w := e.do(req{method: "GET", path: "/", cookie: cookie}); w.Code != http.StatusSeeOther {
		t.Error("the replaced session still works")
	}

	cookie = e.signIn(e.jack)
	if w := e.do(req{method: "POST", path: "/signout", cookie: cookie, origin: "https://evil.example"}); w.Code != http.StatusForbidden {
		t.Errorf("cross-origin sign-out: %d", w.Code)
	}
	w = e.do(req{method: "POST", path: "/signout", cookie: cookie})
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Errorf("sign-out: %d %q", w.Code, w.Header().Get("Set-Cookie"))
	}
	if a := e.lastAudit(); a["action"] != "logout" || a["user"] != "jack" {
		t.Errorf("logout audit record: %v", a)
	}
	if w := e.do(req{method: "GET", path: "/", cookie: cookie}); w.Code != http.StatusSeeOther {
		t.Error("session still works after sign-out")
	}
}

func TestSessionExpires(t *testing.T) {
	e := newEnv(t)
	cookie := e.signIn(e.jack)
	e.clock.t = e.clock.t.Add(8*time.Hour - time.Second)
	if w := e.do(req{method: "GET", path: "/", cookie: cookie}); w.Code != http.StatusOK {
		t.Fatalf("session ended early: %d", w.Code)
	}
	e.clock.t = e.clock.t.Add(time.Second)
	if w := e.do(req{method: "GET", path: "/", cookie: cookie}); w.Code != http.StatusSeeOther {
		t.Errorf("session outlived 8 h: %d", w.Code)
	}
}

func TestFinishRejects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		a      signOpts
		mutate func(e *env, f *finishRequest)
		r      func(r *req)
		status int
		reason string
	}{
		{name: "not user verified", a: signOpts{flags: 0x01}, status: 403, reason: "assertion_flags"},
		{name: "not user present", a: signOpts{flags: 0x04}, status: 403, reason: "assertion_flags"},
		{name: "wrong RP", a: signOpts{flags: 0x05, rpID: "jack.farm"}, status: 403, reason: "assertion_rp"},
		{name: "registration", a: signOpts{flags: 0x05, typ: "webauthn.create"}, status: 403, reason: "assertion_type"},
		{name: "other origin", a: signOpts{flags: 0x05, origin: "https://evil.auth.jack.farm"}, status: 403, reason: "assertion_origin"},
		{name: "cross-origin iframe", a: signOpts{flags: 0x05, extra: `,"crossOrigin":true`}, status: 403, reason: "assertion_origin"},
		{name: "wrong key", a: signOpts{flags: 0x05, resign: true}, status: 403, reason: "assertion_sig_mismatch"},
		{name: "signature not DER", a: signOpts{flags: 0x05, sigBytes: []byte{1, 2, 3}}, status: 403, reason: "assertion_sig_mismatch"},
		{name: "unknown credential", a: signOpts{flags: 0x05, credID: []byte("not enrolled")}, status: 403, reason: "assertion_credential"},
		{name: "other user's credential", a: signOpts{flags: 0x05}, mutate: func(e *env, f *finishRequest) {
			f.CredentialID = base64.RawURLEncoding.EncodeToString(e.guest.id)
		}, status: 403, reason: "assertion_sig_mismatch"},
		{name: "challenge from another begin", a: signOpts{flags: 0x05}, mutate: func(e *env, f *finishRequest) {
			f.ID, _ = e.begin()
		}, status: 403, reason: "assertion_challenge"},
		{name: "unknown challenge ID", a: signOpts{flags: 0x05}, mutate: func(e *env, f *finishRequest) {
			f.ID = "nope"
		}, status: 403, reason: "login_challenge"},
		{name: "expired challenge", a: signOpts{flags: 0x05}, mutate: func(e *env, f *finishRequest) {
			e.clock.t = e.clock.t.Add(3 * time.Minute)
		}, status: 403, reason: "login_challenge"},
		{name: "padded base64", a: signOpts{flags: 0x05}, mutate: func(e *env, f *finishRequest) {
			f.Signature += "=="
		}, status: 400, reason: "assertion_malformed"},
		{name: "std base64", a: signOpts{flags: 0x05}, mutate: func(e *env, f *finishRequest) {
			f.ClientDataJSON = base64.StdEncoding.EncodeToString([]byte("??>>"))
		}, status: 400, reason: "assertion_malformed"},
		{name: "empty signature", a: signOpts{flags: 0x05}, mutate: func(e *env, f *finishRequest) {
			f.Signature = ""
		}, status: 400, reason: "assertion_malformed"},
		{name: "unknown field", a: signOpts{flags: 0x05}, r: func(r *req) {
			r.body = strings.Replace(mustJSON(r.body), `{`, `{"userHandle":"x",`, 1)
		}, status: 400, reason: "assertion_malformed"},
		{name: "trailing data", a: signOpts{flags: 0x05}, r: func(r *req) {
			r.body = mustJSON(r.body) + "{}"
		}, status: 400, reason: "assertion_malformed"},
		{name: "too large", a: signOpts{flags: 0x05}, mutate: func(e *env, f *finishRequest) {
			f.Signature = strings.Repeat("A", maxBody)
		}, status: 400, reason: "assertion_malformed"},
		{name: "form content type", a: signOpts{flags: 0x05}, r: func(r *req) {
			r.header = http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
		}, status: 400, reason: "assertion_malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			id, ch := e.begin()
			f := e.jack.sign(t, ch, tc.a)
			f.ID = id
			if tc.mutate != nil {
				tc.mutate(e, &f)
			}
			r := req{method: "POST", path: "/signin/finish", body: f}
			if tc.r != nil {
				tc.r(&r)
			}
			w := e.do(r)
			if w.Code != tc.status {
				t.Errorf("status %d, want %d: %s", w.Code, tc.status, w.Body)
			}
			if w.Header().Get("Set-Cookie") != "" {
				t.Error("refused sign-in set a cookie")
			}
			if a := e.lastAudit(); a["action"] != "login" || a["result"] != "deny" || a["reason"] != tc.reason {
				t.Errorf("audit %v, want reason %s", a, tc.reason)
			}
		})
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// A challenge allows one attempt, failed or not.
func TestChallengeSingleUse(t *testing.T) {
	e := newEnv(t)
	id, ch := e.begin()
	bad := e.jack.sign(t, ch, signOpts{flags: 0x01})
	bad.ID = id
	if w := e.do(req{method: "POST", path: "/signin/finish", body: bad}); w.Code != 403 {
		t.Fatalf("bad attempt: %d", w.Code)
	}
	good := e.jack.sign(t, ch, signOpts{flags: 0x05})
	good.ID = id
	if w := e.do(req{method: "POST", path: "/signin/finish", body: good}); w.Code != 403 {
		t.Errorf("second attempt on one challenge: %d", w.Code)
	}
	if a := e.lastAudit(); a["reason"] != "login_challenge" {
		t.Errorf("audit %v", a)
	}
}

func TestCrossOrigin(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{"/signin/begin", "/signin/finish", "/signout"} {
		for _, o := range []string{"-", "null", "https://evil.example", "http://id.auth.jack.farm", "https://id.auth.jack.farm:443"} {
			if w := e.do(req{method: "POST", path: path, body: struct{}{}, origin: o}); w.Code != http.StatusForbidden {
				t.Errorf("%s with Origin %q: %d", path, o, w.Code)
			}
		}
	}
	if e.srv.challenges.Len() != 0 {
		t.Error("a cross-origin begin stored a challenge")
	}
}

func TestBeginRateLimit(t *testing.T) {
	e := newEnv(t)
	for i := range addrBurst {
		if w := e.do(req{method: "POST", path: "/signin/begin", body: struct{}{}}); w.Code != 200 {
			t.Fatalf("begin %d: %d", i, w.Code)
		}
	}
	if w := e.do(req{method: "POST", path: "/signin/begin", body: struct{}{}}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("past the burst: %d", w.Code)
	}
	// Another address, or the same one through Caddy, has its own bucket.
	if w := e.do(req{method: "POST", path: "/signin/begin", body: struct{}{}, remote: "10.0.0.6:1"}); w.Code != 200 {
		t.Errorf("other address: %d", w.Code)
	}
	if w := e.do(req{method: "POST", path: "/signin/begin", body: struct{}{}, remote: "127.0.0.1:1",
		header: http.Header{"X-Forwarded-For": {"10.0.0.5"}}}); w.Code != http.StatusTooManyRequests {
		t.Errorf("same address through Caddy: %d", w.Code)
	}
	e.clock.t = e.clock.t.Add(addrEvery)
	if w := e.do(req{method: "POST", path: "/signin/begin", body: struct{}{}}); w.Code != 200 {
		t.Errorf("after refill: %d", w.Code)
	}
}

func TestChallengeStoreFull(t *testing.T) {
	e := newEnv(t)
	for i := range maxChallenges {
		// A fresh address each time, so the rate limit doesn't get there first.
		w := e.do(req{method: "POST", path: "/signin/begin", body: struct{}{}, remote: fmt.Sprintf("10.1.%d.%d:1", i/256, i%256)})
		if w.Code != 200 {
			t.Fatalf("begin %d: %d", i, w.Code)
		}
	}
	if w := e.do(req{method: "POST", path: "/signin/begin", body: struct{}{}}); w.Code != http.StatusServiceUnavailable {
		t.Errorf("full store: %d", w.Code)
	}
}

func TestClientAddr(t *testing.T) {
	for _, tc := range []struct {
		remote string
		xff    []string
		want   string
	}{
		{"10.0.0.5:1", nil, "10.0.0.5"},
		{"10.0.0.5:1", []string{"1.2.3.4"}, "10.0.0.5"}, // only the host's own proxy is believed
		{"127.0.0.1:1", nil, "127.0.0.1"},
		{"127.0.0.1:1", []string{"10.0.0.7"}, "10.0.0.7"},
		{"[::1]:1", []string{"1.1.1.1, 10.0.0.7"}, "10.0.0.7"},
		{"127.0.0.1:1", []string{"1.1.1.1", "2001:db8::1"}, "2001:db8::1"},
		{"127.0.0.1:1", []string{"::ffff:10.0.0.7"}, "10.0.0.7"},
		{"127.0.0.1:1", []string{"fe80::1%eth0"}, "fe80::1"},
		{"127.0.0.1:1", []string{"garbage"}, "127.0.0.1"},
		{"[::ffff:10.0.0.5]:1", nil, "10.0.0.5"},
		{"not an address", nil, "invalid IP"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		r.Header["X-Forwarded-For"] = tc.xff
		if got := clientAddr(r).String(); got != tc.want {
			t.Errorf("%s %q: %s, want %s", tc.remote, tc.xff, got, tc.want)
		}
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"":                             "/",
		"/":                            "/",
		"/device":                      "/device",
		"/authorize?client=g&state=x":  "/authorize?client=g&state=x",
		"//evil.example":               "/",
		"/\\evil.example":              "/",
		"https://evil.example/":        "/",
		"evil":                         "/",
		"/a b":                         "/",
		"/a\tb":                        "/",
		"/é":                           "/",
		"/" + strings.Repeat("a", 512): "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHeadersAndStatic(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{"/signin", "/static/passkey.js", "/static/style.css"} {
		w := e.do(req{method: "GET", path: path})
		if w.Code != 200 {
			t.Errorf("%s: %d", path, w.Code)
		}
		if w.Header().Get("Content-Security-Policy") != csp || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: headers %v", path, w.Header())
		}
	}
	if w := e.do(req{method: "GET", path: "/static/"}); w.Code != http.StatusNotFound {
		t.Errorf("static directory listing: %d", w.Code)
	}
	if w := e.do(req{method: "GET", path: "/signin"}); w.Header().Get("Cache-Control") != "no-store" {
		t.Error("pages are cacheable")
	}
	// Every request has one diagnostic line.
	if n := strings.Count(e.log.String(), `"log":"diag"`); n != 5 {
		t.Errorf("%d diagnostic lines, want 5", n)
	}
}
