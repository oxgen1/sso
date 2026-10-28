package idp

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/oxgen1/sso/internal/config"
	"github.com/oxgen1/sso/internal/ratelimit"
	"github.com/oxgen1/sso/lib/assertion"
	"github.com/oxgen1/sso/lib/cert"
)

// reasonChallenge is an assertion whose challenge was never issued, has
// expired, was used already, or was issued for the other purpose (a sign-in
// challenge can't approve a device, nor the reverse). The other reasons are
// lib/assertion's.
const reasonChallenge = "login_challenge"

// challenge is a pending WebAuthn get. For a device approval, userCode is
// the request it approves; for a sign-in it's empty.
type challenge struct {
	bytes    []byte
	userCode string
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	sess, _, expires, ok := s.session(r)
	if !ok {
		http.Redirect(w, r, "/signin", http.StatusSeeOther)
		return
	}
	render(w, http.StatusOK, "home.html", map[string]string{
		"User":    sess.User,
		"Passkey": sess.Passkey,
		"Until":   expires.Local().Format("15:04 MST"),
	})
}

// signinPage shows the sign-in button, or, with a session already, goes
// straight on to next.
func (s *Server) signinPage(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	if _, _, _, ok := s.session(r); ok {
		http.Redirect(w, r, next, http.StatusSeeOther) // #nosec G710 -- safeNext allows only paths on this host
		return
	}
	render(w, http.StatusOK, "signin.html", map[string]string{"RPID": s.cfg.RPID, "Next": next})
}

type beginResponse struct {
	ID        string `json:"id"`
	Challenge string `json:"challenge"`
	RPID      string `json:"rpId"`
	Timeout   int64  `json:"timeout"`
}

// begin hands out a challenge for navigator.credentials.get. There's no
// allowCredentials: the browser offers the passkeys it has for the RP ID,
// and finish finds the user from the credential ID.
func (s *Server) begin(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "Cross-origin request.")
		return
	}
	s.newChallenge(w, r, "")
}

func (s *Server) newChallenge(w http.ResponseWriter, r *http.Request, userCode string) {
	if !s.addrLimit.Allow(ratelimit.AddrKey(clientAddr(r))) {
		s.log.Warn("passkey rate limit", "log", "diag", "request_id", requestID(r), "client_ip", clientAddr(r).String())
		writeError(w, http.StatusTooManyRequests, "Too many attempts. Wait a minute and try again.")
		return
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails
	id, _, err := s.challenges.Put(challenge{bytes: b, userCode: userCode})
	if err != nil {
		s.log.Warn("challenge store full", "log", "diag", "request_id", requestID(r))
		writeError(w, http.StatusServiceUnavailable, "Too many sign-ins in progress. Try again shortly.")
		return
	}
	writeJSON(w, http.StatusOK, beginResponse{
		ID:        id,
		Challenge: base64.RawURLEncoding.EncodeToString(b),
		RPID:      s.cfg.RPID,
		Timeout:   webauthnTimeout.Milliseconds(),
	})
}

// finishRequest is the response of navigator.credentials.get, each field
// unpadded base64url, plus the ID begin gave with the challenge.
type finishRequest struct {
	ID                string `json:"id"`
	CredentialID      string `json:"credentialId"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
}

func (f *finishRequest) assertion() (*assertion.Assertion, error) {
	var a assertion.Assertion
	for _, p := range []struct {
		name string
		in   string
		out  *[]byte
	}{
		{"credentialId", f.CredentialID, &a.CredentialID},
		{"authenticatorData", f.AuthenticatorData, &a.AuthenticatorData},
		{"clientDataJSON", f.ClientDataJSON, &a.ClientDataJSON},
		{"signature", f.Signature, &a.Signature},
	} {
		b, err := base64.RawURLEncoding.Strict().DecodeString(p.in)
		if err != nil || len(b) == 0 {
			return nil, fmt.Errorf("%s isn't unpadded base64url", p.name)
		}
		*p.out = b
	}
	return &a, nil
}

// finish checks the assertion and starts a session.
func (s *Server) finish(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "Cross-origin request.")
		return
	}
	u, pk, _, attrs, ok := s.checkAssertion(w, r, "login", false)
	if !ok {
		return
	}
	token, _, err := s.sessions.Put(Session{User: u.Claims.User, Passkey: pk.Name})
	if err != nil {
		s.log.Warn("session store", "log", "diag", "request_id", requestID(r), "err", err.Error())
		writeError(w, http.StatusServiceUnavailable, "Too many sessions. Try again later.")
		return
	}
	// A new sign-in replaces the browser's old session rather than leaving
	// it live in memory.
	if old, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.Delete(old.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionTTL / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	s.audit(r, "login", "allow", "", attrs...)
	writeJSON(w, http.StatusOK, map[string]string{"user": u.Claims.User})
}

// checkAssertion reads a finishRequest and checks it: sign-in and device
// approval share everything but what happens after. The challenge is taken
// before anything else is checked, so each one allows a single attempt, and
// it must have been issued for a device approval exactly when device is set.
// On failure it audits action as denied and answers the browser. On success
// it returns the user, the passkey, the challenge's user code, and the audit
// attributes that name them.
func (s *Server) checkAssertion(w http.ResponseWriter, r *http.Request, action string, device bool) (
	*config.User, config.Passkey, string, []any, bool,
) {
	var req finishRequest
	if err := decodeJSON(w, r, &req); err != nil {
		s.denyAssertion(w, r, action, string(assertion.ReasonMalformed), err)
		return nil, config.Passkey{}, "", nil, false
	}
	ch, ok := s.challenges.Take(req.ID)
	if !ok || (ch.userCode != "") != device {
		s.denyAssertion(w, r, action, reasonChallenge, nil)
		return nil, config.Passkey{}, "", nil, false
	}
	a, err := req.assertion()
	if err != nil {
		s.denyAssertion(w, r, action, string(assertion.ReasonMalformed), err)
		return nil, config.Passkey{}, "", nil, false
	}
	credID := base64.RawURLEncoding.EncodeToString(a.CredentialID)
	u, pk, ok := s.cfg.PasskeyOwner(a.CredentialID)
	if !ok {
		s.denyAssertion(w, r, action, string(assertion.ReasonCredential), nil, "passkey_cred_id", credID)
		return nil, config.Passkey{}, "", nil, false
	}
	attrs := []any{"user", u.Claims.User, "passkey", pk.Name, "passkey_cred_id", credID}
	if err := s.verifier.CheckChallenge(a, ch.bytes, []cert.Passkey{pk.Passkey}); err != nil {
		s.denyAssertion(w, r, action, string(assertion.ReasonOf(err)), err, attrs...)
		return nil, config.Passkey{}, "", nil, false
	}
	return u, pk, ch.userCode, attrs, true
}

// denyAssertion audits a refused assertion, logs err for diagnosis, and
// tells the browser no more than that it was refused.
func (s *Server) denyAssertion(w http.ResponseWriter, r *http.Request, action, reason string, err error, attrs ...any) {
	s.audit(r, action, "deny", reason, attrs...)
	if err != nil {
		s.log.Info("assertion refused", "log", "diag", "request_id", requestID(r), "err", err.Error())
	}
	status, msg := http.StatusForbidden, "That passkey wasn't accepted. Is it enrolled?"
	switch reason {
	case string(assertion.ReasonMalformed):
		status, msg = http.StatusBadRequest, "Malformed request."
	case reasonChallenge:
		msg = "That took too long. Try again."
	case string(assertion.ReasonFlags):
		msg = "The authenticator didn't verify you (PIN or biometric)."
	}
	writeError(w, status, msg)
}

func (s *Server) signout(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "Cross-origin request.")
		return
	}
	if sess, token, _, ok := s.session(r); ok {
		s.sessions.Delete(token)
		s.audit(r, "logout", "allow", "", "user", sess.User)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/signin", http.StatusSeeOther)
}
