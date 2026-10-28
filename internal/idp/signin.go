package idp

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/oxgen1/sso/internal/ratelimit"
	"github.com/oxgen1/sso/lib/assertion"
	"github.com/oxgen1/sso/lib/cert"
)

// reasonChallenge is a sign-in whose challenge was never issued, has expired
// or was used already. The other reasons are lib/assertion's.
const reasonChallenge = "login_challenge"

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	sess, _, expires, ok := s.session(r)
	if !ok {
		http.Redirect(w, r, "/signin", http.StatusSeeOther)
		return
	}
	render(w, "home.html", map[string]string{
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
	render(w, "signin.html", map[string]string{"RPID": s.cfg.RPID, "Next": next})
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
	if !s.beginLimit.Allow(ratelimit.AddrKey(clientAddr(r))) {
		s.log.Warn("sign-in rate limit", "log", "diag", "request_id", requestID(r), "client_ip", clientAddr(r).String())
		writeError(w, http.StatusTooManyRequests, "Too many sign-in attempts. Wait a minute and try again.")
		return
	}
	challenge := make([]byte, 32)
	_, _ = rand.Read(challenge) // never fails
	id, _, err := s.challenges.Put(challenge)
	if err != nil {
		s.log.Warn("challenge store full", "log", "diag", "request_id", requestID(r))
		writeError(w, http.StatusServiceUnavailable, "Too many sign-ins in progress. Try again shortly.")
		return
	}
	writeJSON(w, http.StatusOK, beginResponse{
		ID:        id,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
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

// finish checks the assertion and starts a session. The challenge is taken
// before anything else is checked, so each one allows a single attempt.
func (s *Server) finish(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "Cross-origin request.")
		return
	}
	var req finishRequest
	if err := decodeJSON(w, r, &req); err != nil {
		s.denyLogin(w, r, string(assertion.ReasonMalformed), err)
		return
	}
	challenge, ok := s.challenges.Take(req.ID)
	if !ok {
		s.denyLogin(w, r, reasonChallenge, nil)
		return
	}
	a, err := req.assertion()
	if err != nil {
		s.denyLogin(w, r, string(assertion.ReasonMalformed), err)
		return
	}
	credID := base64.RawURLEncoding.EncodeToString(a.CredentialID)
	u, pk, ok := s.cfg.PasskeyOwner(a.CredentialID)
	if !ok {
		s.denyLogin(w, r, string(assertion.ReasonCredential), nil, "passkey_cred_id", credID)
		return
	}
	if err := s.verifier.CheckChallenge(a, challenge, []cert.Passkey{pk.Passkey}); err != nil {
		s.denyLogin(w, r, string(assertion.ReasonOf(err)), err,
			"user", u.Claims.User, "passkey", pk.Name, "passkey_cred_id", credID)
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
	s.audit(r, "login", "allow", "", "user", u.Claims.User, "passkey", pk.Name, "passkey_cred_id", credID)
	writeJSON(w, http.StatusOK, map[string]string{"user": u.Claims.User})
}

// denyLogin audits a failed sign-in, logs err for diagnosis, and tells the
// browser no more than that it failed.
func (s *Server) denyLogin(w http.ResponseWriter, r *http.Request, reason string, err error, attrs ...any) {
	s.audit(r, "login", "deny", reason, attrs...)
	if err != nil {
		s.log.Info("sign-in refused", "log", "diag", "request_id", requestID(r), "err", err.Error())
	}
	status, msg := http.StatusForbidden, "Sign-in failed. Is this passkey enrolled?"
	switch reason {
	case string(assertion.ReasonMalformed):
		status, msg = http.StatusBadRequest, "Sign-in failed: malformed request."
	case reasonChallenge:
		msg = "Sign-in took too long. Try again."
	case string(assertion.ReasonFlags):
		msg = "Sign-in failed: the authenticator didn't verify you (PIN or biometric)."
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
