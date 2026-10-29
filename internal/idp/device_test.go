package idp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oxgen1/sso/lib/cert"
)

var formHeader = http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}

// device is farm's side of the flow.
type device struct {
	key *ecdsa.PrivateKey
	csr string
}

func newDevice(t *testing.T, tmpl *x509.CertificateRequest) *device {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if tmpl == nil {
		tmpl = &x509.CertificateRequest{}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return &device{key: key, csr: base64.RawURLEncoding.EncodeToString(der)}
}

// form posts v as farm would, with no Origin, and returns the JSON response
// with every value as a string.
func (e *env) form(path, remote string, v url.Values, xff ...string) (int, map[string]string) {
	e.t.Helper()
	h := formHeader.Clone()
	if xff != nil {
		h["X-Forwarded-For"] = xff
	}
	w := e.do(req{method: "POST", path: path, body: v.Encode(), header: h, origin: "-", remote: remote})
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		e.t.Fatalf("%s: %d %q", path, w.Code, w.Body)
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		out[k] = fmt.Sprint(v)
	}
	return w.Code, out
}

// requestCode starts the flow from remote and returns the device code and
// the user code.
func (e *env) requestCode(d *device, remote string) (string, string) {
	e.t.Helper()
	code, out := e.form("/device/code", remote, url.Values{"client_id": {"farm"}, "csr": {d.csr}})
	if code != http.StatusOK {
		e.t.Fatalf("device code: %d %v", code, out)
	}
	return out["device_code"], out["user_code"]
}

func (e *env) poll(deviceCode string) (int, map[string]string) {
	e.t.Helper()
	return e.form("/device/token", "", url.Values{
		"grant_type": {deviceGrant}, "client_id": {"farm"}, "device_code": {deviceCode},
	})
}

// approve has a approve the request on the device page, and returns the
// status and the JSON answer of whichever step failed, or of the last.
func (e *env) approve(a *authenticator, userCode string, o signOpts) (int, map[string]string) {
	e.t.Helper()
	w := e.do(req{method: "POST", path: "/device/begin", body: map[string]string{"userCode": userCode}})
	if w.Code != http.StatusOK {
		return w.Code, jsonMap(e.t, w.Body.Bytes())
	}
	var b beginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		e.t.Fatal(err)
	}
	return e.finishApproval(a, b, o)
}

func (e *env) beginApproval(userCode string) beginResponse {
	e.t.Helper()
	w := e.do(req{method: "POST", path: "/device/begin", body: map[string]string{"userCode": userCode}})
	var b beginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil || w.Code != http.StatusOK {
		e.t.Fatalf("device begin: %d %s", w.Code, w.Body)
	}
	return b
}

func (e *env) finishApproval(a *authenticator, b beginResponse, o signOpts) (int, map[string]string) {
	e.t.Helper()
	ch, _ := base64.RawURLEncoding.DecodeString(b.Challenge)
	if o.flags == 0 {
		o.flags = 0x05
	}
	f := a.sign(e.t, ch, o)
	f.ID = b.ID
	w := e.do(req{method: "POST", path: "/device/approve", body: f})
	return w.Code, jsonMap(e.t, w.Body.Bytes())
}

func jsonMap(t *testing.T, b []byte) map[string]string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%q: %v", b, err)
	}
	return m
}

// deny posts the deny form and returns the page.
func (e *env) deny(userCode string) (int, string) {
	e.t.Helper()
	w := e.do(req{method: "POST", path: "/device/deny", header: formHeader, body: url.Values{"user_code": {userCode}}.Encode()})
	return w.Code, w.Body.String()
}

func TestDeviceFlow(t *testing.T) {
	e := newEnv(t)
	d := newDevice(t, nil)
	code, out := e.form("/device/code", "", url.Values{"client_id": {"farm"}, "csr": {d.csr}, "scope": {"ignored"}})
	if code != http.StatusOK {
		t.Fatalf("device code: %d %v", code, out)
	}
	userCode := out["user_code"]
	if len(userCode) != 9 || userCode[4] != '-' {
		t.Errorf("user code %q", userCode)
	}
	if !strings.HasPrefix(out["device_code"], strings.ReplaceAll(userCode, "-", "")+".") || len(out["device_code"]) < 9+26 {
		t.Errorf("device code %q", out["device_code"])
	}
	if out["verification_uri"] != origin+"/device" ||
		out["verification_uri_complete"] != origin+"/device?user_code="+userCode ||
		out["expires_in"] != "600" || out["interval"] != "5" {
		t.Errorf("response: %v", out)
	}

	e.clock.t = e.clock.t.Add(deviceInterval)
	if _, out := e.poll(out["device_code"]); out["error"] != "authorization_pending" {
		t.Errorf("before approval: %v", out)
	}

	// No session needed: the passkey is the approval.
	page := "/device?user_code=" + strings.ToLower(userCode)
	w := e.do(req{method: "GET", path: page})
	for _, want := range []string{userCode, "10.0.0.5", strings.ReplaceAll(keyFingerprint(&d.key.PublicKey), "+", "&#43;"), `data-code="` + userCode + `"`, `action="/device/deny"`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("confirm page lacks %q:\n%s", want, w.Body)
		}
	}
	if status, out := e.approve(e.jack, userCode, signOpts{}); status != 200 || out["message"] != "Approved for jack. Go back to the device." {
		t.Fatalf("approve: %d %v", status, out)
	}
	a := e.lastAudit()
	if a["action"] != "device_approve" || a["result"] != "allow" || a["user"] != "jack" || a["passkey"] != "yubikey" ||
		a["passkey_cred_id"] != base64.RawURLEncoding.EncodeToString(e.jack.id) || a["device_ip"] != "10.0.0.5" {
		t.Errorf("approve audit: %v", a)
	}
	if e.srv.sessions.Len() != 0 {
		t.Error("approving started a session")
	}

	// Approved, but polled too soon.
	if _, out := e.poll(out["device_code"]); out["error"] != "slow_down" {
		t.Errorf("fast poll: %v", out)
	}
	e.clock.t = e.clock.t.Add(2 * deviceInterval)
	status, tok := e.poll(out["device_code"])
	if status != http.StatusOK {
		t.Fatalf("token: %d %v", status, tok)
	}
	block, rest := pem.Decode([]byte(tok["certificate"]))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) > 0 {
		t.Fatalf("certificate %q", tok["certificate"])
	}
	v, err := cert.NewVerifier(e.ca.Cert.Raw, "statusd")
	if err != nil {
		t.Fatal(err)
	}
	v.Now = e.clock.now
	c, err := cert.Parse(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:1"
	if _, _, err := v.Verify(r, block.Bytes, c.Serial); err != nil {
		t.Errorf("statusd refuses the certificate: %v", err)
	}
	if c.User != "jack" || !c.HasRole("write") || !c.Key.Equal(&d.key.PublicKey) || len(c.Passkeys) != 1 ||
		!c.NotAfter.Equal(e.clock.t.Add(cert.Lifetime).Truncate(time.Second)) {
		t.Errorf("certificate: %+v", c)
	}
	a = e.lastAudit()
	if a["action"] != "certificate" || a["result"] != "allow" || a["cert_serial"] != c.Serial || a["user"] != "jack" || a["passkey"] != "yubikey" {
		t.Errorf("certificate audit: %v", a)
	}

	// One certificate per code.
	e.clock.t = e.clock.t.Add(time.Minute)
	if _, out := e.poll(out["device_code"]); out["error"] != "expired_token" {
		t.Errorf("second collection: %v", out)
	}
	if w := e.do(req{method: "GET", path: page}); !strings.Contains(w.Body.String(), "No request has that code") {
		t.Errorf("code still pending after issue:\n%s", w.Body)
	}
}

func TestDeviceDeny(t *testing.T) {
	e := newEnv(t)
	deviceCode, userCode := e.requestCode(newDevice(t, nil), "")
	if status, body := e.deny(userCode); status != 200 || !strings.Contains(body, "Denied.") {
		t.Fatalf("deny: %d %s", status, body)
	}
	if a := e.lastAudit(); a["result"] != "deny" || a["reason"] != "user_denied" || a["user"] != nil {
		t.Errorf("deny audit: %v", a)
	}
	if status, out := e.approve(e.jack, userCode, signOpts{}); status != http.StatusNotFound || out["error"] != msgHandled {
		t.Errorf("approve after deny: %d %v", status, out)
	}
	e.clock.t = e.clock.t.Add(deviceInterval)
	if _, out := e.poll(deviceCode); out["error"] != "access_denied" {
		t.Errorf("poll: %v", out)
	}
	e.clock.t = e.clock.t.Add(deviceInterval)
	if _, out := e.poll(deviceCode); out["error"] != "expired_token" {
		t.Errorf("poll after denial: %v", out)
	}
}

// guest's certificates are good only from 192.168.1.0/24.
func TestDeviceSource(t *testing.T) {
	e := newEnv(t)
	deviceCode, userCode := e.requestCode(newDevice(t, nil), "10.0.0.5:1")
	if status, out := e.approve(e.guest, userCode, signOpts{}); status != http.StatusForbidden || !strings.Contains(out["error"], "came from 10.0.0.5") {
		t.Errorf("approve from outside the sources: %d %v", status, out)
	}
	if a := e.lastAudit(); a["result"] != "deny" || a["reason"] != "source" || a["user"] != "guest" {
		t.Errorf("audit: %v", a)
	}
	e.clock.t = e.clock.t.Add(deviceInterval)
	if _, out := e.poll(deviceCode); out["error"] != "access_denied" {
		t.Errorf("poll: %v", out)
	}

	// From 192.168.1.9, through Caddy.
	_, out := e.form("/device/code", "127.0.0.1:1", url.Values{"client_id": {"farm"}, "csr": {newDevice(t, nil).csr}}, "192.168.1.9")
	deviceCode, userCode = out["device_code"], out["user_code"]
	if status, out := e.approve(e.guest, userCode, signOpts{}); status != 200 {
		t.Errorf("approve from inside the sources: %d %v", status, out)
	}
	e.clock.t = e.clock.t.Add(deviceInterval)
	if status, out := e.poll(deviceCode); status != http.StatusOK {
		t.Errorf("poll: %v", out)
	}
}

func TestDeviceSlowDown(t *testing.T) {
	e := newEnv(t)
	deviceCode, _ := e.requestCode(newDevice(t, nil), "")
	for _, step := range []struct {
		wait time.Duration
		want string
	}{
		{0, "slow_down"},               // interval 5 s → 10 s
		{5 * time.Second, "slow_down"}, // → 15 s
		{15 * time.Second, "authorization_pending"},
		{14 * time.Second, "slow_down"}, // → 20 s
		{20 * time.Second, "authorization_pending"},
	} {
		e.clock.t = e.clock.t.Add(step.wait)
		if _, out := e.poll(deviceCode); out["error"] != step.want {
			t.Errorf("after %v: %v, want %s", step.wait, out, step.want)
		}
	}
}

func TestDeviceExpires(t *testing.T) {
	e := newEnv(t)
	deviceCode, userCode := e.requestCode(newDevice(t, nil), "")
	e.clock.t = e.clock.t.Add(deviceTTL)
	if status, out := e.approve(e.jack, userCode, signOpts{}); status != http.StatusNotFound || !strings.Contains(out["error"], "No request has that code") {
		t.Errorf("approve after expiry: %d %v", status, out)
	}
	if _, out := e.poll(deviceCode); out["error"] != "expired_token" {
		t.Errorf("poll after expiry: %v", out)
	}

	// The request expires while the passkey prompt is open.
	_, userCode = e.requestCode(newDevice(t, nil), "")
	e.clock.t = e.clock.t.Add(deviceTTL - time.Minute)
	b := e.beginApproval(userCode)
	e.clock.t = e.clock.t.Add(time.Minute)
	if status, out := e.finishApproval(e.jack, b, signOpts{}); status != http.StatusNotFound || !strings.Contains(out["error"], "expired") {
		t.Errorf("expired mid-approval: %d %v", status, out)
	}
	if a := e.lastAudit(); a["reason"] != "device_expired" || a["user"] != "jack" {
		t.Errorf("audit: %v", a)
	}
}

func TestDeviceCodeRejects(t *testing.T) {
	e := newEnv(t)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384CSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, p384)
	p256 := newDevice(t, nil)
	tampered, _ := base64.RawURLEncoding.DecodeString(p256.csr)
	tampered[len(tampered)-1] ^= 1
	enc := base64.RawURLEncoding.EncodeToString

	for name, tc := range map[string]struct {
		body   string
		header http.Header
		want   string
	}{
		"json":          {`{"client_id":"farm"}`, http.Header{"Content-Type": {"application/json"}}, "invalid_request"},
		"repeated":      {"client_id=farm&client_id=farm&csr=" + p256.csr, nil, "invalid_request"},
		"bad encoding":  {"client_id=%zz", nil, "invalid_request"},
		"client":        {"client_id=grafana&csr=" + p256.csr, nil, "invalid_client"},
		"no client":     {"csr=" + p256.csr, nil, "invalid_client"},
		"no csr":        {"client_id=farm", nil, "invalid_request"},
		"padded csr":    {"client_id=farm&csr=" + p256.csr + "%3D", nil, "invalid_request"},
		"not DER":       {"client_id=farm&csr=" + enc([]byte("hello")), nil, "invalid_request"},
		"subject":       {"client_id=farm&csr=" + newDevice(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "root"}}).csr, nil, "invalid_request"},
		"extensions":    {"client_id=farm&csr=" + newDevice(t, &x509.CertificateRequest{DNSNames: []string{"x"}}).csr, nil, "invalid_request"},
		"P-384":         {"client_id=farm&csr=" + enc(p384CSR), nil, "invalid_request"},
		"SHA-384":       {"client_id=farm&csr=" + newDevice(t, &x509.CertificateRequest{SignatureAlgorithm: x509.ECDSAWithSHA384}).csr, nil, "invalid_request"},
		"bad signature": {"client_id=farm&csr=" + enc(tampered), nil, "invalid_request"},
	} {
		t.Run(name, func(t *testing.T) {
			h := tc.header
			if h == nil {
				h = formHeader
			}
			w := e.do(req{method: "POST", path: "/device/code", body: tc.body, header: h, remote: fmt.Sprintf("10.2.0.%d:1", len(name))})
			var out map[string]string
			_ = json.Unmarshal(w.Body.Bytes(), &out)
			if w.Code != http.StatusBadRequest || out["error"] != tc.want {
				t.Errorf("%d %v, want %s", w.Code, out, tc.want)
			}
		})
	}
	if e.srv.devices.Len() != 0 {
		t.Errorf("%d devices stored", e.srv.devices.Len())
	}
}

func TestTokenRejects(t *testing.T) {
	e := newEnv(t)
	deviceCode, _ := e.requestCode(newDevice(t, nil), "")
	userCode, secret, _ := strings.Cut(deviceCode, ".")
	e.clock.t = e.clock.t.Add(deviceInterval)
	for name, tc := range map[string]struct {
		v    url.Values
		want string
	}{
		"grant":        {url.Values{"grant_type": {"authorization_code"}, "client_id": {"farm"}, "device_code": {deviceCode}}, "unsupported_grant_type"},
		"client":       {url.Values{"grant_type": {deviceGrant}, "client_id": {"x"}, "device_code": {deviceCode}}, "invalid_client"},
		"unknown":      {url.Values{"grant_type": {deviceGrant}, "client_id": {"farm"}, "device_code": {"BCDFGHJK." + secret}}, "expired_token"},
		"no secret":    {url.Values{"grant_type": {deviceGrant}, "client_id": {"farm"}, "device_code": {userCode}}, "invalid_grant"},
		"wrong secret": {url.Values{"grant_type": {deviceGrant}, "client_id": {"farm"}, "device_code": {userCode + "." + secret[1:] + "A"}}, "invalid_grant"},
		"empty":        {url.Values{}, "unsupported_grant_type"},
	} {
		if _, out := e.form("/device/token", "", tc.v); out["error"] != tc.want {
			t.Errorf("%s: %v, want %s", name, out, tc.want)
		}
	}
	if a := e.lastAudit(); a["action"] != "certificate" || a["result"] != "deny" || a["reason"] != "device_code" {
		t.Errorf("wrong secret audit: %v", a)
	}
	// None of that counted as a poll.
	if _, out := e.poll(deviceCode); out["error"] != "authorization_pending" {
		t.Errorf("real poll: %v", out)
	}
}

func TestDevicePage(t *testing.T) {
	e := newEnv(t)
	w := e.do(req{method: "GET", path: "/device"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `name="user_code"`) {
		t.Errorf("entry form: %d\n%s", w.Code, w.Body)
	}
	for _, code := range []string{"AAAA-AAAA", "BCDF", "BCDF-GHJK-L", "BCDF-GHJK"} {
		w := e.do(req{method: "GET", path: "/device?user_code=" + code})
		if !strings.Contains(w.Body.String(), "No request has that code") {
			t.Errorf("%s:\n%s", code, w.Body)
		}
	}
	// Four lookups so far, out of ten.
	for range lookupBurst - 4 {
		e.do(req{method: "GET", path: "/device?user_code=BCDFGHJK"})
	}
	if w := e.do(req{method: "GET", path: "/device?user_code=BCDFGHJK"}); !strings.Contains(w.Body.String(), "Too many tries") {
		t.Errorf("past the limit:\n%s", w.Body)
	}
	if status, out := e.approve(e.jack, "BCDFGHJK", signOpts{}); status != http.StatusNotFound || out["error"] != "Too many tries. Wait a minute." {
		t.Errorf("begin past the limit: %d %v", status, out)
	}
	if _, body := e.deny("BCDFGHJK"); !strings.Contains(body, "Too many tries") {
		t.Errorf("deny past the limit:\n%s", body)
	}
	// The limit is per address.
	if w := e.do(req{method: "GET", path: "/device?user_code=BCDFGHJK", remote: "10.0.0.6:1"}); strings.Contains(w.Body.String(), "Too many tries") {
		t.Error("10.0.0.6 shares 10.0.0.5's limit")
	}
}

func TestDeviceApproveRejects(t *testing.T) {
	e := newEnv(t)
	deviceCode, userCode := e.requestCode(newDevice(t, nil), "")
	b := e.beginApproval(userCode)

	for name, tc := range map[string]struct {
		r    req
		want int
	}{
		"begin cross origin":   {req{method: "POST", path: "/device/begin", body: map[string]string{"userCode": userCode}, origin: "https://evil.example"}, http.StatusForbidden},
		"begin form":           {req{method: "POST", path: "/device/begin", body: "userCode=" + userCode, header: formHeader}, http.StatusBadRequest},
		"begin unknown field":  {req{method: "POST", path: "/device/begin", body: `{"userCode":"` + userCode + `","user":"jack"}`}, http.StatusBadRequest},
		"approve cross origin": {req{method: "POST", path: "/device/approve", body: struct{}{}, origin: "https://evil.example"}, http.StatusForbidden},
		"approve form":         {req{method: "POST", path: "/device/approve", body: "id=" + b.ID, header: formHeader}, http.StatusBadRequest},
		"deny cross origin":    {req{method: "POST", path: "/device/deny", body: "user_code=" + userCode, header: formHeader, origin: "https://evil.example"}, http.StatusForbidden},
		"deny JSON":            {req{method: "POST", path: "/device/deny", body: map[string]string{"user_code": userCode}}, http.StatusBadRequest},
	} {
		if w := e.do(tc.r); w.Code != tc.want {
			t.Errorf("%s: %d, want %d", name, w.Code, tc.want)
		}
	}

	// A sign-in challenge can't approve a device, nor the reverse.
	id, ch := e.begin()
	if status, _ := e.finishApproval(e.jack, beginResponse{ID: id, Challenge: base64.RawURLEncoding.EncodeToString(ch)}, signOpts{}); status != http.StatusForbidden {
		t.Errorf("sign-in challenge for approval: %d", status)
	}
	if a := e.lastAudit(); a["action"] != "device_approve" || a["reason"] != reasonChallenge {
		t.Errorf("audit: %v", a)
	}
	ch, _ = base64.RawURLEncoding.DecodeString(b.Challenge)
	f := e.jack.sign(t, ch, signOpts{flags: 0x05})
	f.ID = b.ID
	if w := e.do(req{method: "POST", path: "/signin/finish", body: f}); w.Code != http.StatusForbidden || len(w.Result().Cookies()) > 0 {
		t.Errorf("approval challenge for sign-in: %d", w.Code)
	}
	if a := e.lastAudit(); a["action"] != "login" || a["reason"] != reasonChallenge {
		t.Errorf("audit: %v", a)
	}

	// The checks are sign-in's: one case each is enough here.
	for name, tc := range map[string]struct {
		a      *authenticator
		o      signOpts
		reason string
	}{
		"not enrolled": {newAuthenticator(t), signOpts{}, "assertion_credential"},
		"no UV":        {e.jack, signOpts{flags: 0x01}, "assertion_flags"},
		"wrong key":    {e.jack, signOpts{resign: true}, "assertion_sig_mismatch"},
	} {
		if status, _ := e.approve(tc.a, userCode, tc.o); status != http.StatusForbidden {
			t.Errorf("%s: %d", name, status)
		}
		if a := e.lastAudit(); a["action"] != "device_approve" || a["reason"] != tc.reason {
			t.Errorf("%s: audit %v", name, a)
		}
	}

	// Two tabs: both get a challenge, the first approval wins.
	b1, b2 := e.beginApproval(userCode), e.beginApproval(userCode)
	if status, out := e.finishApproval(e.jack, b1, signOpts{}); status != 200 {
		t.Fatalf("approve: %d %v", status, out)
	}
	if status, out := e.finishApproval(e.guest, b2, signOpts{}); status != http.StatusConflict || out["error"] != msgHandled {
		t.Errorf("second tab: %d %v", status, out)
	}
	if a := e.lastAudit(); a["reason"] != "device_handled" || a["user"] != "guest" {
		t.Errorf("audit: %v", a)
	}
	// Denying an approved request changes nothing.
	if _, body := e.deny(userCode); !strings.Contains(body, msgHandled) {
		t.Errorf("deny after approve:\n%s", body)
	}
	e.clock.t = e.clock.t.Add(deviceInterval)
	if status, out := e.poll(deviceCode); status != http.StatusOK {
		t.Errorf("poll: %d %v", status, out)
	}
}

func TestDeviceLimits(t *testing.T) {
	e := newEnv(t)
	d := newDevice(t, nil)
	for range addrBurst {
		e.requestCode(d, "10.3.0.0:1")
	}
	if code, out := e.form("/device/code", "10.3.0.0:1", url.Values{"client_id": {"farm"}, "csr": {d.csr}}); code != http.StatusTooManyRequests {
		t.Errorf("past the burst: %d %v", code, out)
	}
	for i := addrBurst; i < maxDevices; i++ {
		e.requestCode(d, fmt.Sprintf("10.4.%d.%d:1", i/256, i%256))
	}
	if code, out := e.form("/device/code", "10.5.0.0:1", url.Values{"client_id": {"farm"}, "csr": {d.csr}}); code != http.StatusServiceUnavailable {
		t.Errorf("full: %d %v", code, out)
	}
}

func TestUserCode(t *testing.T) {
	seen := map[byte]bool{}
	for range 200 {
		c := newUserCode()
		if n, ok := normalizeUserCode(c); !ok || n != c {
			t.Fatalf("%q doesn't normalize to itself", c)
		}
		for i := range len(c) {
			seen[c[i]] = true
		}
	}
	if len(seen) != len(userCodeAlphabet) {
		t.Errorf("200 codes used %d letters", len(seen))
	}
	for in, want := range map[string]string{
		"bcdf-ghjk": "BCDFGHJK", " BCDF GHJK ": "BCDFGHJK", "BCDFGHJ": "", "BCDFGHJKL": "", "BCDF-GHJA": "", "BCDF_GHJK": "",
	} {
		if got, _ := normalizeUserCode(in); got != want {
			t.Errorf("normalizeUserCode(%q) = %q, want %q", in, got, want)
		}
	}
}

// However many polls race, a code yields one certificate.
func TestDeviceIssuesOnce(t *testing.T) {
	e := newEnv(t)
	deviceCode, userCode := e.requestCode(newDevice(t, nil), "")
	e.approve(e.jack, userCode, signOpts{})
	e.clock.t = e.clock.t.Add(deviceInterval)
	body := url.Values{"grant_type": {deviceGrant}, "client_id": {"farm"}, "device_code": {deviceCode}}.Encode()
	codes := make(chan int, 20)
	var wg sync.WaitGroup
	for range cap(codes) {
		wg.Go(func() {
			r := httptest.NewRequest("POST", "/device/token", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			e.srv.ServeHTTP(w, r)
			codes <- w.Code
		})
	}
	wg.Wait()
	close(codes)
	n := 0
	for c := range codes {
		if c == http.StatusOK {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d certificates", n)
	}
}
