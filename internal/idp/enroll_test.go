package idp

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// regOpts changes what the authenticator sends when registering.
type regOpts struct {
	typ    string
	credID []byte
}

// register makes a passkey on a, as navigator.credentials.create would with
// attestation "none".
func (a *authenticator) register(t *testing.T, challenge []byte, o regOpts) (attObj, clientData string) {
	t.Helper()
	if o.typ == "" {
		o.typ = "webauthn.create"
	}
	if o.credID == nil {
		o.credID = a.id
	}
	cd := fmt.Appendf(nil, `{"type":%q,"challenge":%q,"origin":%q}`,
		o.typ, base64.RawURLEncoding.EncodeToString(challenge), origin)
	point, err := a.key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	em, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	key, err := em.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: point[1:33], -3: point[33:]})
	if err != nil {
		t.Fatal(err)
	}
	rp := sha256.Sum256([]byte(rpID))
	ad := append(rp[:], 0x45, 0, 0, 0, 0) // UP, UV, AT
	ad = append(ad, make([]byte, 16)...)  // AAGUID
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(o.credID)))
	ad = append(append(ad, o.credID...), key...)
	obj, err := em.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad})
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc(obj), enc(cd)
}

func (e *env) enrollLink(user string) string {
	e.t.Helper()
	link, exp, err := EnrollLink(e.srv.cfg, e.ca, user, e.clock.now())
	if err != nil {
		e.t.Fatal(err)
	}
	if !exp.Equal(e.clock.t.Add(enrollTTL)) {
		e.t.Errorf("expires %v", exp)
	}
	tok, ok := strings.CutPrefix(link, origin+"/enroll/")
	if !ok {
		e.t.Fatalf("link %q", link)
	}
	return tok
}

func (e *env) enrollBegin(tok, name string) (int, enrollBeginResponse, string) {
	e.t.Helper()
	w := e.do(req{method: "POST", path: "/enroll/begin", body: enrollBeginRequest{Token: tok, Name: name}})
	var b enrollBeginResponse
	_ = json.Unmarshal(w.Body.Bytes(), &b)
	return w.Code, b, w.Body.String()
}

func (e *env) enrollFinish(a *authenticator, b enrollBeginResponse, o regOpts) (int, map[string]string) {
	e.t.Helper()
	ch, _ := base64.RawURLEncoding.DecodeString(b.Challenge)
	att, cd := a.register(e.t, ch, o)
	w := e.do(req{method: "POST", path: "/enroll/finish", body: enrollFinishRequest{ID: b.ID, AttestationObject: att, ClientDataJSON: cd}})
	return w.Code, jsonMap(e.t, w.Body.Bytes())
}

func TestEnroll(t *testing.T) {
	e := newEnv(t)
	tok := e.enrollLink("jack")
	laptop := newAuthenticator(t)

	w := e.do(req{method: "GET", path: "/enroll/" + tok})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<strong>jack</strong>") || !strings.Contains(w.Body.String(), `data-token="`+tok+`"`) {
		t.Errorf("page: %d\n%s", w.Code, w.Body)
	}
	if strings.Contains(e.log.String(), tok) {
		t.Error("the token is in the log")
	}

	status, b, body := e.enrollBegin(tok, "laptop")
	if status != 200 {
		t.Fatalf("begin: %d %s", status, body)
	}
	handle, _ := base64.RawURLEncoding.DecodeString(b.UserID)
	if b.User != "jack" || len(handle) != 16 || b.RPID != rpID ||
		len(b.Exclude) != 1 || b.Exclude[0] != base64.RawURLEncoding.EncodeToString(e.jack.id) {
		t.Errorf("begin: %+v", b)
	}
	status, out := e.enrollFinish(laptop, b, regOpts{})
	if status != 200 {
		t.Fatalf("finish: %d %v", status, out)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&laptop.key.PublicKey)
	want := fmt.Sprintf(`{ name = "laptop"; id = %q; publicKey = %q; }`,
		base64.RawURLEncoding.EncodeToString(laptop.id), base64.StdEncoding.EncodeToString(spki))
	if out["snippet"] != want {
		t.Errorf("snippet\n%s, want\n%s", out["snippet"], want)
	}
	if a := e.lastAudit(); a["action"] != "enroll" || a["result"] != "allow" || a["user"] != "jack" ||
		a["passkey"] != "laptop" || a["snippet"] != want {
		t.Errorf("audit: %v", a)
	}

	// The link is used up.
	if w := e.do(req{method: "GET", path: "/enroll/" + tok}); w.Code != http.StatusNotFound {
		t.Errorf("page after use: %d", w.Code)
	}
	if status, _, _ := e.enrollBegin(tok, "laptop2"); status != http.StatusNotFound {
		t.Errorf("begin after use: %d", status)
	}
}

func TestEnrollLink(t *testing.T) {
	e := newEnv(t)
	tok := e.enrollLink("jack")
	user, rest, _ := strings.Cut(tok, ".")
	exp, rest, _ := strings.Cut(rest, ".")
	nonce, mac, _ := strings.Cut(rest, ".")
	forge := func(body string) string { return body + "." + enrollMAC(e.srv.enrollKey, body) }
	later := strconv.FormatInt(e.clock.t.Add(time.Hour).Unix(), 10)

	for name, tok := range map[string]string{
		"other user":     "guest." + exp + "." + nonce + "." + mac,
		"later":          user + "." + later + "." + nonce + "." + mac,
		"bad MAC":        user + "." + exp + "." + nonce + "." + mac[1:] + "A",
		"no MAC":         user + "." + exp + "." + nonce,
		"extra part":     tok + ".x",
		"empty":          "",
		"unknown user":   forge("root." + exp + "." + nonce),
		"bad expiry":     forge(user + ".soon." + nonce),
		"other CA's key": user + "." + exp + "." + nonce + "." + enrollMAC(make([]byte, 32), user+"."+exp+"."+nonce),
	} {
		if _, err := e.srv.parseEnroll(tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := e.srv.parseEnroll(tok); err != nil {
		t.Fatal(err)
	}
	e.clock.t = e.clock.t.Add(enrollTTL)
	if _, err := e.srv.parseEnroll(tok); err == nil {
		t.Error("expired link accepted")
	}
	if _, _, err := EnrollLink(e.srv.cfg, e.ca, "root", e.clock.now()); err == nil {
		t.Error("link for an unknown user")
	}
	if w := e.do(req{method: "GET", path: "/enroll/" + tok}); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "Run sso enroll again") {
		t.Errorf("expired page: %d", w.Code)
	}
}

func TestEnrollRejects(t *testing.T) {
	e := newEnv(t)
	tok := e.enrollLink("jack")
	laptop := newAuthenticator(t)

	for name, tc := range map[string]struct {
		name string
		want int
	}{
		"uppercase": {"Laptop", http.StatusBadRequest},
		"empty":     {"", http.StatusBadRequest},
		"taken":     {"yubikey", http.StatusBadRequest},
	} {
		if status, _, body := e.enrollBegin(tok, tc.name); status != tc.want {
			t.Errorf("%s: %d %s", name, status, body)
		}
	}
	for name, r := range map[string]req{
		"begin cross origin":  {method: "POST", path: "/enroll/begin", body: enrollBeginRequest{Token: tok, Name: "x"}, origin: "https://evil.example"},
		"finish cross origin": {method: "POST", path: "/enroll/finish", body: enrollFinishRequest{}, origin: "https://evil.example"},
	} {
		if w := e.do(r); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if w := e.do(req{method: "POST", path: "/enroll/begin", body: `{"token":"` + tok + `"`}); w.Code != http.StatusBadRequest {
		t.Errorf("begin truncated JSON: %d", w.Code)
	}

	// A sign-in challenge can't enroll, and an enrollment challenge can't
	// sign in.
	id, ch := e.begin()
	if status, _ := e.enrollFinish(laptop, enrollBeginResponse{beginResponse: beginResponse{ID: id, Challenge: base64.RawURLEncoding.EncodeToString(ch)}}, regOpts{}); status != http.StatusForbidden {
		t.Errorf("sign-in challenge: %d", status)
	}
	if a := e.lastAudit(); a["action"] != "enroll" || a["reason"] != reasonChallenge {
		t.Errorf("audit: %v", a)
	}
	_, b, _ := e.enrollBegin(tok, "laptop")
	bch, _ := base64.RawURLEncoding.DecodeString(b.Challenge)
	f := e.jack.sign(t, bch, signOpts{flags: 0x05})
	f.ID = b.ID
	if w := e.do(req{method: "POST", path: "/signin/finish", body: f}); w.Code != http.StatusForbidden {
		t.Errorf("enrollment challenge for sign-in: %d", w.Code)
	}

	for name, tc := range map[string]struct {
		a      *authenticator
		o      regOpts
		reason string
	}{
		"get, not create":  {laptop, regOpts{typ: "webauthn.get"}, "enroll_register"},
		"enrolled already": {e.guest, regOpts{}, "enroll_duplicate"},
	} {
		_, b, _ := e.enrollBegin(tok, "laptop")
		if status, out := e.enrollFinish(tc.a, b, tc.o); status != http.StatusForbidden {
			t.Errorf("%s: %d %v", name, status, out)
		}
		if a := e.lastAudit(); a["action"] != "enroll" || a["reason"] != tc.reason {
			t.Errorf("%s: audit %v", name, a)
		}
	}
	if w := e.do(req{method: "POST", path: "/enroll/finish", body: enrollFinishRequest{ID: "x", AttestationObject: "=", ClientDataJSON: "="}}); w.Code != http.StatusForbidden {
		t.Errorf("unknown challenge: %d", w.Code)
	}
	_, b, _ = e.enrollBegin(tok, "laptop")
	if w := e.do(req{method: "POST", path: "/enroll/finish", body: enrollFinishRequest{ID: b.ID, AttestationObject: "a=", ClientDataJSON: "b"}}); w.Code != http.StatusBadRequest {
		t.Errorf("bad base64: %d", w.Code)
	}

	// Two tabs with one link: only one passkey.
	_, b1, _ := e.enrollBegin(tok, "laptop")
	_, b2, _ := e.enrollBegin(tok, "phone")
	if status, out := e.enrollFinish(laptop, b1, regOpts{}); status != 200 {
		t.Fatalf("first: %d %v", status, out)
	}
	if status, out := e.enrollFinish(newAuthenticator(t), b2, regOpts{}); status != http.StatusForbidden || out["error"] != "This enrollment link was used already." {
		t.Errorf("second: %d %v", status, out)
	}
}
