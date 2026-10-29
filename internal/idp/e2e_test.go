package idp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oxgen1/sso/lib/cert"
	"github.com/oxgen1/sso/lib/httpsig"
)

// issue runs the device flow for d with jack's passkey and returns the
// certificate's DER.
func (e *env) issue(d *device) []byte {
	e.t.Helper()
	deviceCode, userCode := e.requestCode(d, "")
	if status, out := e.approve(e.jack, userCode, signOpts{}); status != http.StatusOK {
		e.t.Fatalf("approve: %d %v", status, out)
	}
	e.clock.t = e.clock.t.Add(deviceInterval)
	status, tok := e.poll(deviceCode)
	block, _ := pem.Decode([]byte(tok["certificate"]))
	if status != http.StatusOK || block == nil {
		e.t.Fatalf("token: %d %v", status, tok)
	}
	return block.Bytes
}

// service is a stand-in for statusd: a real HTTP server whose write route
// checks signatures with lib, as the statusd middleware will.
type service struct {
	srv *httptest.Server
	mu  sync.Mutex
	now time.Time                     // the server's clock, apart from the IdP's
	hv  *httpsig.Verifier[*cert.Cert] // set before the server starts
}

// newService starts a service named name that trusts the CA caDER and
// answers to authority, or to its own address if that's empty.
func newService(t *testing.T, caDER []byte, name, authority string, now time.Time) *service {
	t.Helper()
	s := &service{now: now}
	cv, err := cert.NewVerifier(caDER, name)
	if err != nil {
		t.Fatal(err)
	}
	cv.Now = s.clock
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		v, err := s.hv.Verify(r, body)
		if err != nil {
			http.Error(w, string(httpsig.ReasonOf(err)), http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"user": v.Cert.User, "write": v.Cert.HasRole("write"), "body": string(body)})
	}))
	if authority == "" {
		authority = s.srv.Listener.Addr().String()
	}
	s.hv = &httpsig.Verifier[*cert.Cert]{
		Authorities: []string{authority},
		Cert:        cv.Verify,
		Nonces:      httpsig.NewNonceCache(16),
		Started:     now.Add(-time.Hour),
		Now:         s.clock,
	}
	s.srv.Start()
	t.Cleanup(s.srv.Close)
	return s
}

func (s *service) clock() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now
}

func (s *service) advance(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = s.now.Add(d)
}

// post sends a signed write over the network and returns the status and the
// response body. With replay set, it sends the headers of replay instead of
// signing afresh.
func (s *service) post(t *testing.T, signer *httpsig.Signer, body string, replay http.Header) (int, string, http.Header) {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, s.srv.URL+"/v1/microvms/web/restart?force=0", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if replay != nil {
		r.Header = replay.Clone()
	} else if _, err := signer.Sign(r, []byte(body)); err != nil {
		t.Fatal(err)
	}
	sent := r.Header.Clone()
	resp, err := s.srv.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(out)), sent
}

// TestIssuedCertSignsRequests is the whole path farm will take: a key and
// CSR, the device flow with a passkey, then a signed request over a real
// connection to a service that trusts only the CA.
func TestIssuedCertSignsRequests(t *testing.T) {
	e := newEnv(t)
	d := newDevice(t, nil)
	der := e.issue(d)
	c, err := cert.Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	signer := &httpsig.Signer{Key: d.key, Cert: der, KeyID: c.Serial, Now: e.clock.now}
	statusd := newService(t, e.ca.Cert.Raw, "statusd", "", e.clock.t)

	status, out, sent := statusd.post(t, signer, `{"vm":"web"}`, nil)
	if status != http.StatusOK || out != `{"body":"{\"vm\":\"web\"}","user":"jack","write":true}` {
		t.Fatalf("signed write: %d %s", status, out)
	}
	for name, tc := range map[string]struct {
		setup func() (*service, *httpsig.Signer, http.Header)
		want  httpsig.Reason
	}{
		"replayed": {func() (*service, *httpsig.Signer, http.Header) { return statusd, signer, sent }, httpsig.ReasonReplay},
		"other service": {func() (*service, *httpsig.Signer, http.Header) {
			return newService(t, e.ca.Cert.Raw, "grafana", "", e.clock.t), signer, nil
		}, httpsig.ReasonScope},
		"other CA": {func() (*service, *httpsig.Signer, http.Header) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			other, err := cert.NewCA("test CA", key, e.clock.t, e.clock.t.AddDate(1, 0, 0))
			if err != nil {
				t.Fatal(err)
			}
			return newService(t, other, "statusd", "", e.clock.t), signer, nil
		}, httpsig.ReasonCert},
		"other key": {func() (*service, *httpsig.Signer, http.Header) {
			other := *signer
			other.Key = newDevice(t, nil).key
			return statusd, &other, nil
		}, httpsig.ReasonSigMismatch},
		"other authority": {func() (*service, *httpsig.Signer, http.Header) {
			return newService(t, e.ca.Cert.Raw, "statusd", "farm-1:9200", e.clock.t), signer, nil
		}, httpsig.ReasonAuthority},
	} {
		s, sig, replay := tc.setup()
		if status, out, _ := s.post(t, sig, `{"vm":"web"}`, replay); status != http.StatusUnauthorized || out != string(tc.want) {
			t.Errorf("%s: %d %s, want %s", name, status, out, tc.want)
		}
	}

	// Eight hours on, both clocks agree the certificate has expired, and
	// farm has to log in again.
	e.clock.t = e.clock.t.Add(cert.Lifetime + time.Second)
	statusd.advance(cert.Lifetime + time.Second)
	if status, out, _ := statusd.post(t, signer, `{"vm":"web"}`, nil); status != http.StatusUnauthorized || out != string(httpsig.ReasonCertExpired) {
		t.Errorf("expired: %d %s", status, out)
	}
	d2 := newDevice(t, nil)
	der = e.issue(d2)
	if c, err = cert.Parse(der); err != nil {
		t.Fatal(err)
	}
	signer = &httpsig.Signer{Key: d2.key, Cert: der, KeyID: c.Serial, Now: e.clock.now}
	if status, out, _ := statusd.post(t, signer, `{"vm":"web"}`, nil); status != http.StatusOK || !strings.Contains(out, `"user":"jack"`) {
		t.Errorf("after logging in again: %d %s", status, out)
	}
}
