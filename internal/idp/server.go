// Package idp serves the IdP's pages and endpoints: passkey sign-in, the SSO
// session, the device flow that issues certificates, and enrollment.
package idp

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/oxgen1/sso/internal/config"
	"github.com/oxgen1/sso/internal/ratelimit"
	"github.com/oxgen1/sso/internal/store"
	"github.com/oxgen1/sso/internal/webauthn"
	"github.com/oxgen1/sso/lib/assertion"
	"github.com/oxgen1/sso/lib/cert"
)

// Limits on what's held in memory, and for how long.
const (
	// The SSO session lasts a working day, like a certificate. It's absolute:
	// using it doesn't extend it.
	sessionTTL  = 8 * time.Hour
	maxSessions = 1000

	// The browser gives up on a WebAuthn get after webauthnTimeout; the
	// challenge outlives it so a slow but valid answer isn't refused.
	challengeTTL    = 3 * time.Minute
	webauthnTimeout = 2 * time.Minute
	maxChallenges   = 1000

	// Starting a sign-in or a device request holds something in memory:
	// 10 at once per address, then one every 6 s.
	addrEvery  = 6 * time.Second
	addrBurst  = 10
	maxClients = 10_000

	maxBody = 16 << 10
)

// sessionCookie has the __Host- prefix: the browser only accepts it Secure,
// on Path=/ and with no Domain, so no other host under the RP ID can set it.
const sessionCookie = "__Host-sso"

// csp allows the page's own script and style and nothing else.
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; " +
	"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

//go:embed web
var web embed.FS

var pages = template.Must(template.ParseFS(web, "web/*.html"))

// Session is an SSO session: who signed in, and with which passkey.
type Session struct {
	User    string
	Passkey string
}

// Server is the IdP's HTTP handler.
type Server struct {
	cfg        *config.Config
	ca         *cert.CA
	verifier   *assertion.Verifier
	registrar  *webauthn.RP
	enrollKey  []byte
	enrolled   *store.Store[struct{}] // nonces of used enrollment links
	challenges *store.Store[challenge]
	sessions   *store.Store[Session]
	devices    *store.Store[*deviceAuth]
	deviceMu   sync.Mutex // the mutable fields of every deviceAuth
	addrLimit  *ratelimit.Limiter
	lookLimit  *ratelimit.Limiter
	log        *slog.Logger
	now        func() time.Time
	mux        *http.ServeMux
}

// New returns the IdP for cfg, issuing certificates from ca. Audit and diagnostic records go to log, told
// apart by their "log" attribute; now is the clock for everything but
// latency.
func New(cfg *config.Config, ca *cert.CA, log *slog.Logger, now func() time.Time) (*Server, error) {
	v, err := assertion.NewVerifier(cfg.RPID, cfg.Origin)
	if err != nil {
		return nil, err
	}
	reg, err := webauthn.New(cfg.RPID, cfg.Origin)
	if err != nil {
		return nil, err
	}
	key, err := enrollKey(ca)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:        cfg,
		ca:         ca,
		verifier:   v,
		registrar:  reg,
		enrollKey:  key,
		enrolled:   store.New[struct{}](maxEnrolls, enrollTTL, now),
		challenges: store.New[challenge](maxChallenges, challengeTTL, now),
		sessions:   store.New[Session](maxSessions, sessionTTL, now),
		devices:    store.New[*deviceAuth](maxDevices, deviceTTL, now),
		addrLimit:  ratelimit.New(addrEvery, addrBurst, maxClients, now),
		lookLimit:  ratelimit.New(lookupEvery, lookupBurst, maxClients, now),
		log:        log,
		now:        now,
		mux:        http.NewServeMux(),
	}
	s.mux.HandleFunc("GET /{$}", s.home)
	s.mux.HandleFunc("GET /signin", s.signinPage)
	s.mux.HandleFunc("POST /signin/begin", s.begin)
	s.mux.HandleFunc("POST /signin/finish", s.finish)
	s.mux.HandleFunc("POST /signout", s.signout)
	s.mux.HandleFunc("POST /device/code", s.deviceCode)
	s.mux.HandleFunc("POST /device/token", s.token)
	s.mux.HandleFunc("GET /device", s.devicePage)
	s.mux.HandleFunc("POST /device/begin", s.deviceBegin)
	s.mux.HandleFunc("POST /device/approve", s.deviceApprove)
	s.mux.HandleFunc("POST /device/deny", s.deviceDeny)
	s.mux.HandleFunc("GET /enroll/{token}", s.enrollPage)
	s.mux.HandleFunc("POST /enroll/begin", s.enrollBegin)
	s.mux.HandleFunc("POST /enroll/finish", s.enrollFinish)
	for _, name := range []string{"passkey.js", "style.css"} {
		s.mux.HandleFunc("GET /static/"+name, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-cache")
			http.ServeFileFS(w, r, web, "web/static/"+name)
		})
	}
	return s, nil
}

type requestIDKey struct{}

// ServeHTTP sets the headers every response gets and writes one diagnostic
// line per request.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now() // latency is real time, whatever the clock says
	id := rand.Text()[:16]
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	// same-origin rather than no-referrer: with no-referrer, browsers send
	// Origin: null on form posts, and sameOrigin would refuse sign-out.
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	s.mux.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	// The path only, as a query may carry a code, and not an enrollment
	// link's token.
	path := r.URL.Path
	if strings.HasPrefix(path, "/enroll/") && path != "/enroll/begin" && path != "/enroll/finish" {
		path = "/enroll/…"
	}
	s.log.Info("request", "log", "diag", "request_id", id, "method", r.Method, "path", path,
		"status", sw.status, "client_ip", clientAddr(r).String(), "ms", time.Since(start).Milliseconds())
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func requestID(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey{}).(string)
	return id
}

// audit writes an audit record. Its fields follow docs/design.md#logging;
// the hash chain is still to come.
func (s *Server) audit(r *http.Request, action, result, reason string, attrs ...any) {
	base := []any{"log", "audit", "v", 1, "action", action, "result", result}
	if reason != "" {
		base = append(base, "reason", reason)
	}
	base = append(base, "request_id", requestID(r), "client_ip", clientAddr(r).String(),
		"server_time", s.now().UTC().Format(time.RFC3339))
	s.log.Info(action, append(base, attrs...)...)
}

// clientAddr is the address a request came from. Behind Caddy on the same
// host, that's the last X-Forwarded-For entry: Caddy sets it from the
// connection, and drops whatever the client sent unless the client is a
// trusted proxy, which none is. Anything else on the host is trusted to tell
// the truth. From any other peer, it's the peer.
func clientAddr(r *http.Request) netip.Addr {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	a := peer.Addr().Unmap()
	xff := r.Header.Values("X-Forwarded-For")
	if !a.IsLoopback() || len(xff) == 0 {
		return a
	}
	last := xff[len(xff)-1]
	if i := strings.LastIndexByte(last, ','); i >= 0 {
		last = last[i+1:]
	}
	fwd, err := netip.ParseAddr(strings.TrimSpace(last))
	if err != nil {
		return a
	}
	return fwd.Unmap().WithZone("")
}

// sameOrigin reports whether a state-changing request came from the IdP's
// own pages. SameSite=Strict already keeps the cookie off cross-site
// requests; this also covers the endpoints that don't need one.
func (s *Server) sameOrigin(r *http.Request) bool {
	o := r.Header.Values("Origin")
	return len(o) == 1 && o[0] == s.cfg.Origin
}

// session returns the request's SSO session, and the cookie's token.
func (s *Server) session(r *http.Request) (Session, string, time.Time, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return Session{}, "", time.Time{}, false
	}
	sess, expires, ok := s.sessions.Get(c.Value)
	return sess, c.Value, expires, ok
}

// safeNext returns next if it's a path on this host, and "/" otherwise, so
// the sign-in page can't be made to send anyone elsewhere.
func safeNext(next string) string {
	if len(next) > 512 || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") ||
		strings.ContainsFunc(next, func(c rune) bool { return c < 0x21 || c > 0x7e || c == '\\' }) {
		return "/"
	}
	return next
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		return fmt.Errorf("content type %q", ct)
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError sends msg, which the page shows as it is.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		// Headers are gone by now; the diagnostic line shows the 200, and
		// a template that fails is caught by the tests.
		panic(err)
	}
}
