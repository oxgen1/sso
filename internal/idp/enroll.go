package idp

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/oxgen1/sso/internal/config"
	"github.com/oxgen1/sso/internal/store"
	"github.com/oxgen1/sso/lib/cert"
)

// Enrollment registers a passkey. sso enroll, run on the IdP host, prints a
// link; whoever opens it registers one passkey for that user and gets the
// snippet to paste into the Nix configuration. Nothing is enrolled until
// it's pasted and deployed: the IdP has no user database.
//
// The link is USER.EXPIRES.NONCE.MAC, the MAC an HMAC-SHA256 under a key
// derived from the CA key. So sso enroll and sso serve share nothing but the
// key they both already hold, and only someone who can read it can make a
// link. The server remembers the nonces of used links until they expire.

const (
	enrollTTL  = 10 * time.Minute
	maxEnrolls = 100
	enrollInfo = "sso enroll link v1"
)

// enrollKey derives the link MAC key from the CA key, so the CA key itself
// is only ever used to sign certificates.
func enrollKey(ca *cert.CA) ([]byte, error) {
	secret, err := ca.Key.Bytes()
	if err != nil {
		return nil, err
	}
	return hkdf.Key(sha256.New, secret, nil, enrollInfo, 32)
}

func enrollMAC(key []byte, body string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// EnrollLink returns a link for user to register one passkey, and when it
// expires.
func EnrollLink(cfg *config.Config, ca *cert.CA, user string, now time.Time) (string, time.Time, error) {
	if _, ok := cfg.Users[user]; !ok {
		return "", time.Time{}, fmt.Errorf("no user %q in the configuration", user)
	}
	key, err := enrollKey(ca)
	if err != nil {
		return "", time.Time{}, err
	}
	exp := now.Add(enrollTTL).Truncate(time.Second)
	body := user + "." + strconv.FormatInt(exp.Unix(), 10) + "." + rand.Text()
	return cfg.Origin + "/enroll/" + body + "." + enrollMAC(key, body), exp, nil
}

// enrollment is a checked link.
type enrollment struct {
	user  *config.User
	exp   time.Time
	nonce string
	name  string // the passkey's, once begin has it
}

var errEnrollLink = errors.New("enrollment link invalid, expired or used")

// parseEnroll checks a link's token: the MAC first, so nothing else is
// looked at for a token sso enroll didn't make.
func (s *Server) parseEnroll(tok string) (*enrollment, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 4 {
		return nil, errEnrollLink
	}
	body := strings.Join(parts[:3], ".")
	if !hmac.Equal([]byte(parts[3]), []byte(enrollMAC(s.enrollKey, body))) {
		return nil, errEnrollLink
	}
	u, ok := s.cfg.Users[parts[0]]
	secs, err := strconv.ParseInt(parts[1], 10, 64)
	if !ok || err != nil {
		return nil, errEnrollLink
	}
	exp := time.Unix(secs, 0)
	if _, _, used := s.enrolled.Get(parts[2]); used || !s.now().Before(exp) {
		return nil, errEnrollLink
	}
	return &enrollment{user: u, exp: exp, nonce: parts[2]}, nil
}

// enrollPage shows who the link is for and asks for a name.
func (s *Server) enrollPage(w http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("token")
	e, err := s.parseEnroll(tok)
	if err != nil {
		render(w, http.StatusNotFound, "enroll.html", map[string]string{
			"Error": "This enrollment link is invalid, has expired or was used. Run sso enroll again."})
		return
	}
	render(w, http.StatusOK, "enroll.html", map[string]string{
		"User":  e.user.Claims.User,
		"Until": e.exp.Local().Format("15:04 MST"),
		"Token": tok,
	})
}

type enrollBeginRequest struct {
	Token string `json:"token"`
	Name  string `json:"name"`
}

type enrollBeginResponse struct {
	beginResponse
	User    string   `json:"user"`
	UserID  string   `json:"userId"`
	Exclude []string `json:"exclude"`
}

// enrollBegin hands out a challenge for navigator.credentials.create. The
// name is checked here, before anyone touches a key.
func (s *Server) enrollBegin(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "Cross-origin request.")
		return
	}
	var req enrollBeginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Malformed request.")
		return
	}
	e, err := s.parseEnroll(req.Token)
	if err != nil {
		writeError(w, http.StatusNotFound, "This enrollment link is invalid, has expired or was used.")
		return
	}
	u := e.user
	if !cert.ValidName(req.Name) {
		writeError(w, http.StatusBadRequest, "Name it with a lowercase letter, then lowercase letters, digits or hyphens.")
		return
	}
	if slices.ContainsFunc(u.Passkeys, func(p config.Passkey) bool { return p.Name == req.Name }) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("%s already has a passkey named %s.", u.Claims.User, req.Name))
		return
	}
	e.name = req.Name
	b, ok := s.newChallengeFor(w, r, challenge{enroll: e})
	if !ok {
		return
	}
	// The browser won't make a second passkey on an authenticator that
	// already has one of these.
	exclude := make([]string, len(u.Passkeys))
	for i, p := range u.Passkeys {
		exclude[i] = base64.RawURLEncoding.EncodeToString(p.ID)
	}
	// The user handle only has to be stable and not personal; sign-in finds
	// the user from the credential ID.
	handle := sha256.Sum256([]byte("sso user handle\x00" + u.Claims.User))
	writeJSON(w, http.StatusOK, enrollBeginResponse{
		beginResponse: b,
		User:          u.Claims.User,
		UserID:        base64.RawURLEncoding.EncodeToString(handle[:16]),
		Exclude:       exclude,
	})
}

type enrollFinishRequest struct {
	ID                string `json:"id"`
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
}

// enrollFinish checks the registration and answers with the snippet. The
// link is used up only by a registration that succeeds.
func (s *Server) enrollFinish(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "Cross-origin request.")
		return
	}
	var req enrollFinishRequest
	if err := decodeJSON(w, r, &req); err != nil {
		s.denyEnroll(w, r, "enroll_malformed", err)
		return
	}
	ch, ok := s.challenges.Take(req.ID)
	if !ok || ch.enroll == nil {
		s.denyEnroll(w, r, reasonChallenge, nil)
		return
	}
	e := ch.enroll
	attrs := []any{"user", e.user.Claims.User, "passkey", e.name}
	attObj, err1 := base64.RawURLEncoding.Strict().DecodeString(req.AttestationObject)
	cd, err2 := base64.RawURLEncoding.Strict().DecodeString(req.ClientDataJSON)
	if err := errors.Join(err1, err2); err != nil {
		s.denyEnroll(w, r, "enroll_malformed", err, attrs...)
		return
	}
	pk, err := s.registrar.Register(attObj, cd, ch.bytes)
	if err != nil {
		s.denyEnroll(w, r, "enroll_register", err, attrs...)
		return
	}
	credID := base64.RawURLEncoding.EncodeToString(pk.ID)
	attrs = append(attrs, "passkey_cred_id", credID)
	if u, _, ok := s.cfg.PasskeyOwner(pk.ID); ok {
		s.denyEnroll(w, r, "enroll_duplicate", fmt.Errorf("already enrolled for %s", u.Claims.User), attrs...)
		return
	}
	// Marking the link used is what makes it single-use; the challenge
	// expires before the link does, so the entry outlives every challenge
	// issued for it.
	if _, err := s.enrolled.Add(e.nonce, struct{}{}); err != nil {
		reason := "enroll_used"
		if errors.Is(err, store.ErrFull) {
			reason = "enroll_full"
		}
		s.denyEnroll(w, r, reason, err, attrs...)
		return
	}
	spki, err := x509.MarshalPKIXPublicKey(pk.Key)
	if err != nil {
		s.denyEnroll(w, r, "enroll_register", err, attrs...)
		return
	}
	pub := base64.StdEncoding.EncodeToString(spki)
	snippet := fmt.Sprintf(`{ name = %q; id = %q; publicKey = %q; }`, e.name, credID, pub)
	// The snippet is in the audit log too, so whoever deploys it can take it
	// from there rather than from whoever registered.
	s.audit(r, "enroll", "allow", "", append(attrs, "public_key", pub, "snippet", snippet)...)
	writeJSON(w, http.StatusOK, map[string]string{"snippet": snippet, "user": e.user.Claims.User})
}

func (s *Server) denyEnroll(w http.ResponseWriter, r *http.Request, reason string, err error, attrs ...any) {
	s.audit(r, "enroll", "deny", reason, attrs...)
	if err != nil {
		s.log.Info("enrollment refused", "log", "diag", "request_id", requestID(r), "err", err.Error())
	}
	status, msg := http.StatusForbidden, "The passkey couldn't be registered."
	switch reason {
	case "enroll_malformed":
		status, msg = http.StatusBadRequest, "Malformed request."
	case reasonChallenge:
		msg = "That took too long. Try again."
	case "enroll_duplicate":
		msg = "That passkey is already enrolled."
	case "enroll_used":
		msg = "This enrollment link was used already."
	case "enroll_full":
		status, msg = http.StatusServiceUnavailable, "Too many enrollments. Try again in a few minutes."
	}
	writeError(w, status, msg)
}
