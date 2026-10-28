package idp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/oxgen1/sso/internal/ratelimit"
	"github.com/oxgen1/sso/internal/store"
)

// The device flow (RFC 8628) is how mvm gets a certificate: it sends a CSR
// for a key it made, prints a code, and polls while its user approves the
// request in the browser with a passkey. The passkey both says who the user
// is and approves this one request; the SSO session plays no part. The
// certificate is issued when the device next polls.

const (
	// deviceClient is the only client that uses the device flow.
	deviceClient = "mvm"
	deviceGrant  = "urn:ietf:params:oauth:grant-type:device_code"

	deviceTTL      = 10 * time.Minute
	deviceInterval = 5 * time.Second
	maxDevices     = 100

	// Looking up a user code is limited per address, so nobody can search
	// the code space: 10 at once, then one every 30 s.
	lookupEvery = 30 * time.Second
	lookupBurst = 10
)

// RFC 8628 §6.1: base-20 consonants, so no words and no look-alike
// characters. Eight of them are about 34.5 bits.
const (
	userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
	userCodeLen      = 8
)

// deviceAuth is a pending device request, stored under its user code. The
// device code is the user code, a dot and secret: the user code finds the
// entry, and only the device knows the secret.
type deviceAuth struct {
	secret string
	key    *ecdsa.PublicKey
	keyFP  string
	addr   netip.Addr
	at     time.Time

	// Under Server.deviceMu.
	interval time.Duration
	lastPoll time.Time
	user     string // who approved it
	passkey  string // and with which passkey
	denied   bool
	issued   bool
}

func (d *deviceAuth) handled() bool { return d.user != "" || d.denied }

// newUserCode returns userCodeLen letters from userCodeAlphabet, each
// uniform: bytes of 240 or more are thrown away, as 240 is 12 × 20.
func newUserCode() string {
	code := make([]byte, 0, userCodeLen)
	buf := make([]byte, 2*userCodeLen)
	for len(code) < userCodeLen {
		_, _ = rand.Read(buf) // never fails
		for _, b := range buf {
			if b < 240 && len(code) < userCodeLen {
				code = append(code, userCodeAlphabet[b%20])
			}
		}
	}
	return string(code)
}

// normalizeUserCode accepts a code as people type it: any case, with
// hyphens or spaces.
func normalizeUserCode(s string) (string, bool) {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(s))
	if len(s) != userCodeLen || strings.Trim(s, userCodeAlphabet) != "" {
		return "", false
	}
	return s, true
}

// formatUserCode shows a code as XXXX-XXXX.
func formatUserCode(code string) string {
	return code[:4] + "-" + code[4:]
}

// keyFingerprint is SHA-256 of the SubjectPublicKeyInfo, written as OpenSSH
// writes key fingerprints. mvm prints the same, so the two can be compared.
func keyFingerprint(key *ecdsa.PublicKey) string {
	spki, _ := x509.MarshalPKIXPublicKey(key) // a P-256 key always marshals
	sum := sha256.Sum256(spki)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// parseCSR returns the key of a PKCS #10 request, unpadded base64url DER.
// The request's signature proves the device holds the key. Its subject must
// be empty and it may ask for no extensions: what goes in the certificate
// comes from the configuration.
func parseCSR(s string) (*ecdsa.PublicKey, error) {
	der, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, errors.New("csr isn't unpadded base64url")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	switch {
	case !ok || key.Curve != elliptic.P256():
		return nil, errors.New("csr key isn't P-256")
	case csr.SignatureAlgorithm != x509.ECDSAWithSHA256:
		return nil, fmt.Errorf("csr signature algorithm %v", csr.SignatureAlgorithm)
	case len(csr.Subject.Names) > 0 || len(csr.Extensions) > 0:
		return nil, errors.New("csr has a subject or extensions")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	return key, nil
}

// readForm reads an application/x-www-form-urlencoded body. A parameter may
// appear once (RFC 6749 §3.1); unknown ones are left for the caller to
// ignore.
func readForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		return nil, fmt.Errorf("content type %q", ct)
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		return nil, err
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	for k, v := range form {
		if len(v) != 1 {
			return nil, fmt.Errorf("parameter %q repeated", k)
		}
	}
	return form, nil
}

// oauthError sends an RFC 6749 §5.2 error. desc is for whoever reads mvm's
// output.
func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

// deviceCode is the device authorization endpoint (RFC 8628 §3.1), with one
// extra parameter: csr.
func (s *Server) deviceCode(w http.ResponseWriter, r *http.Request) {
	addr := clientAddr(r)
	if !s.addrLimit.Allow(ratelimit.AddrKey(addr)) {
		s.log.Warn("device code rate limit", "log", "diag", "request_id", requestID(r), "client_ip", addr.String())
		oauthError(w, http.StatusTooManyRequests, "slow_down", "Too many requests from this address. Wait a minute.")
		return
	}
	form, err := readForm(w, r)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if form.Get("client_id") != deviceClient {
		oauthError(w, http.StatusBadRequest, "invalid_client", "Unknown client_id.")
		return
	}
	key, err := parseCSR(form.Get("csr"))
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "csr: "+err.Error())
		return
	}
	d := &deviceAuth{
		secret:   rand.Text(),
		key:      key,
		keyFP:    keyFingerprint(key),
		addr:     addr,
		at:       s.now(),
		interval: deviceInterval,
		lastPoll: s.now(),
	}
	// 100 pending codes in 2.56 × 10¹⁰: a collision is rare, three in a
	// row means something is wrong with the random source.
	var code string
	for range 3 {
		code = newUserCode()
		if _, err = s.devices.Add(code, d); !errors.Is(err, store.ErrExists) {
			break
		}
	}
	if err != nil {
		s.log.Warn("device store", "log", "diag", "request_id", requestID(r), "err", err.Error())
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "Too many sign-ins in progress. Try again shortly.")
		return
	}
	s.audit(r, "device_code", "allow", "", "user_code", code, "key", d.keyFP)
	complete := s.cfg.Origin + "/device?" + url.Values{"user_code": {formatUserCode(code)}}.Encode()
	writeJSON(w, http.StatusOK, deviceCodeResponse{
		DeviceCode:              code + "." + d.secret,
		UserCode:                formatUserCode(code),
		VerificationURI:         s.cfg.Origin + "/device",
		VerificationURIComplete: complete,
		ExpiresIn:               int64(deviceTTL / time.Second),
		Interval:                int64(deviceInterval / time.Second),
	})
}

// token is the token endpoint for the device grant (RFC 8628 §3.4). The
// errors are RFC 8628's; on success the response isn't an OAuth access
// token but the certificate, as PEM.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	form, err := readForm(w, r)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if form.Get("grant_type") != deviceGrant {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "Only the device code grant is supported.")
		return
	}
	if form.Get("client_id") != deviceClient {
		oauthError(w, http.StatusBadRequest, "invalid_client", "Unknown client_id.")
		return
	}
	code, secret, _ := strings.Cut(form.Get("device_code"), ".")
	d, _, ok := s.devices.Get(code)
	if !ok {
		oauthError(w, http.StatusBadRequest, "expired_token", "The code has expired. Start again.")
		return
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte(d.secret)) != 1 {
		s.audit(r, "certificate", "deny", "device_code", "user_code", code)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "Wrong device code.")
		return
	}

	s.deviceMu.Lock()
	now := s.now()
	if now.Sub(d.lastPoll) < d.interval {
		d.interval += 5 * time.Second // RFC 8628 §3.5
		d.lastPoll = now
		s.deviceMu.Unlock()
		oauthError(w, http.StatusBadRequest, "slow_down", "Polling too fast.")
		return
	}
	d.lastPoll = now
	user, passkey, denied, issued := d.user, d.passkey, d.denied, d.issued
	if user != "" {
		d.issued = true
	}
	s.deviceMu.Unlock()

	switch {
	case issued:
		oauthError(w, http.StatusBadRequest, "expired_token", "The certificate was already issued.")
		return
	case denied:
		s.devices.Delete(code)
		oauthError(w, http.StatusBadRequest, "access_denied", "The request was denied.")
		return
	case user == "":
		oauthError(w, http.StatusBadRequest, "authorization_pending", "Waiting for approval.")
		return
	}
	s.devices.Delete(code)
	der, c, err := s.ca.Issue(d.key, s.cfg.Users[user].Claims)
	if err != nil {
		s.log.Error("issue", "log", "diag", "request_id", requestID(r), "user", user, "err", err.Error())
		oauthError(w, http.StatusInternalServerError, "server_error", "The certificate couldn't be issued.")
		return
	}
	s.audit(r, "certificate", "allow", "", "user", user, "passkey", passkey, "cert_serial", c.Serial, "user_code", code,
		"key", d.keyFP, "not_after", c.NotAfter.UTC().Format(time.RFC3339))
	writeJSON(w, http.StatusOK, map[string]string{
		"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	})
}

// devicePage asks for the code the device shows, then shows the request so
// it can be approved with a passkey or denied.
func (s *Server) devicePage(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("user_code")
	if raw == "" {
		render(w, http.StatusOK, "device.html", devicePageData{})
		return
	}
	code, d, msg := s.lookupDevice(r, raw)
	if msg != "" {
		render(w, http.StatusOK, "device.html", devicePageData{Error: msg})
		return
	}
	render(w, http.StatusOK, "device.html", devicePageData{Request: &deviceView{
		Code: formatUserCode(code),
		Addr: d.addr.String(),
		Key:  d.keyFP,
		At:   d.at.Local().Format("15:04:05 MST"),
	}})
}

type devicePageData struct {
	Error   string
	Done    string
	Request *deviceView
}

type deviceView struct {
	Code, Addr, Key, At string
}

const msgHandled = "That request was already approved or denied."

// lookupDevice finds a pending request by the code someone typed, and
// otherwise says what to tell them.
func (s *Server) lookupDevice(r *http.Request, raw string) (string, *deviceAuth, string) {
	if !s.lookLimit.Allow(ratelimit.AddrKey(clientAddr(r))) {
		s.log.Warn("device lookup rate limit", "log", "diag", "request_id", requestID(r), "client_ip", clientAddr(r).String())
		return "", nil, "Too many tries. Wait a minute."
	}
	code, ok := normalizeUserCode(raw)
	var d *deviceAuth
	if ok {
		d, _, ok = s.devices.Get(code)
	}
	if !ok {
		return "", nil, "No request has that code. Codes last 10 minutes; check it against the device."
	}
	s.deviceMu.Lock()
	defer s.deviceMu.Unlock()
	if d.handled() {
		return "", nil, msgHandled
	}
	return code, d, ""
}

// deviceBegin hands out a challenge for approving one request.
func (s *Server) deviceBegin(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "Cross-origin request.")
		return
	}
	var req struct {
		UserCode string `json:"userCode"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Malformed request.")
		return
	}
	code, _, msg := s.lookupDevice(r, req.UserCode)
	if msg != "" {
		writeError(w, http.StatusNotFound, msg)
		return
	}
	s.newChallenge(w, r, code)
}

// deviceApprove checks the passkey assertion and approves the request its
// challenge was issued for. The device gets the certificate when it next
// polls.
func (s *Server) deviceApprove(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "Cross-origin request.")
		return
	}
	u, pk, code, attrs, ok := s.checkAssertion(w, r, "device_approve", true)
	if !ok {
		return
	}
	attrs = append(attrs, "user_code", code)
	d, _, ok := s.devices.Get(code)
	if !ok { // expired between the challenge and the touch
		s.audit(r, "device_approve", "deny", "device_expired", attrs...)
		writeError(w, http.StatusNotFound, "The request expired. Run mvm login again.")
		return
	}
	attrs = append(attrs, "device_ip", d.addr.String(), "key", d.keyFP)

	s.deviceMu.Lock()
	var reason string
	switch {
	case d.handled(): // decided in another tab since the challenge
		reason = "device_handled"
	case !allowedFrom(u.Claims.Sources, d.addr):
		// The certificate would be useless from there, and a request from
		// somewhere the user can't be is more likely phishing than travel.
		d.denied = true
		reason = "source"
	default:
		d.user, d.passkey = u.Claims.User, pk.Name
	}
	s.deviceMu.Unlock()

	switch reason {
	case "device_handled":
		s.audit(r, "device_approve", "deny", reason, attrs...)
		writeError(w, http.StatusConflict, msgHandled)
	case "source":
		s.audit(r, "device_approve", "deny", reason, attrs...)
		writeError(w, http.StatusForbidden, fmt.Sprintf("The request came from %s, which isn't an address "+
			"your certificates can be used from. It was denied.", d.addr))
	default:
		s.audit(r, "device_approve", "allow", "", attrs...)
		writeJSON(w, http.StatusOK, map[string]string{"message": "Approved for " + u.Claims.User + ". Go back to the device."})
	}
}

// deviceDeny refuses a request. It needs no passkey: anyone with the code
// can refuse, and refusing grants nothing.
func (s *Server) deviceDeny(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "Cross-origin request.")
		return
	}
	form, err := readForm(w, r)
	if err != nil {
		render(w, http.StatusBadRequest, "device.html", devicePageData{Error: "Malformed request."})
		return
	}
	code, d, msg := s.lookupDevice(r, form.Get("user_code"))
	if msg != "" {
		render(w, http.StatusOK, "device.html", devicePageData{Error: msg})
		return
	}
	s.deviceMu.Lock()
	handled := d.handled()
	if !handled {
		d.denied = true
	}
	s.deviceMu.Unlock()
	if handled {
		render(w, http.StatusOK, "device.html", devicePageData{Error: msgHandled})
		return
	}
	s.audit(r, "device_approve", "deny", "user_denied", "user_code", code, "device_ip", d.addr.String(), "key", d.keyFP)
	render(w, http.StatusOK, "device.html", devicePageData{Done: "Denied. The device has been told."})
}

// allowedFrom reports whether a certificate limited to sources can be used
// from addr. No sources means anywhere.
func allowedFrom(sources []netip.Prefix, addr netip.Addr) bool {
	if len(sources) == 0 {
		return true
	}
	for _, p := range sources {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
