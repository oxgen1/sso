# Integration

How to put a service, a web app or a client behind the SSO. Running the IdP itself is in [setup.md](setup.md).

> **Status:** written ahead of the code, as the finished system should work. The Go examples use the real API of `lib/httpsig` and `lib/cert`, which exist; `lib/assertion`, the Nix options, `sso-proxy` and `mvm` are still to be built.

There are three ways in:

| You have | Use | Example |
|---|---|---|
| A Go HTTP API | `lib` in-process: verify signed requests per route | [statusd](#statusd) |
| A web app you don't want to change | Caddy `forward_auth` to `sso-proxy` | [Grafana](#web-apps-behind-caddy) |
| A command line or script | `mvm req`, or `httpsig.Signer` from Go | [Clients](#clients) |

## statusd

statusd checks every request itself with `github.com/oxgen1/sso/lib`. It needs only the CA certificate and the names it answers to: no network access to the IdP, no secrets.

### Nix

```nix
services.statusd = {
  enable = true;
  listenAddresses = [ "10.0.0.30:9020" ];          # LAN: reads only
  writeListenAddresses = [ "10.100.0.1:9021" ];    # WireGuard: reads and writes

  sso = {
    enable = true;
    service = "statusd";                           # must be in users.<name>.services
    caCertificate = ./sso/ca.pem;
    # Every Host value clients use, with the port. A request signed for any
    # other name is rejected, so it can't be replayed against another service.
    authorities = [ "farm-1:9020" "10.0.0.30:9020" "farm-1.wg:9021" "10.100.0.1:9021" ];
  };
};
```

Write and destructive routes are only registered on `writeListenAddresses` (and the Unix socket). Signatures prove who sent a request and that it wasn't changed; they don't hide it, so writes go over WireGuard.

### Go

Build two verifiers at start-up, one for reads and one for writes. They differ only in the nonce cache: reads don't change anything, so they aren't worth a cache entry.

```go
import (
	"github.com/oxgen1/sso/lib/cert"
	"github.com/oxgen1/sso/lib/httpsig"
)

func newAuth(cfg Config) (*Auth, error) {
	block, _ := pem.Decode(cfg.CACertPEM)
	if block == nil {
		return nil, errors.New("CA certificate isn't PEM")
	}
	certs, err := cert.NewVerifier(block.Bytes, cfg.Service)
	if err != nil {
		return nil, err
	}
	reads := &httpsig.Verifier[*cert.Cert]{
		Authorities: cfg.Authorities,
		Cert:        certs.Verify,
	}
	writes := *reads
	writes.Nonces = httpsig.NewNonceCache(10_000)
	writes.Started = time.Now() // writes signed before this are rejected
	return &Auth{reads: reads, writes: &writes}, nil
}
```

Each route declares its tier where it's registered. A route registered without one doesn't compile:

```go
mux.Handle("GET /v1/status", a.Read(s.status))
mux.Handle("POST /v1/microvms/{name}/restart", a.Write(s.restart))
mux.Handle("DELETE /v1/microvms/{name}", a.Destructive(s.terminate))
```

The middleware reads the body (the digest covers it), verifies, checks the role, and logs one audit record:

```go
func (a *Auth) handle(tier Tier, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		v := a.reads
		if tier != Read {
			v = a.writes
		}
		got, err := v.Verify(r, body)
		if err != nil {
			a.deny(r, tier, httpsig.ReasonOf(err), err) // audit: reason; diagnostic: err
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		c := got.Cert
		switch {
		case tier == Write && !c.HasRole("write"),
			tier == Destructive && !c.HasRole("admin"):
			a.deny(r, tier, "role", nil)
			w.WriteHeader(http.StatusForbidden)
			return
		case tier == Destructive:
			if err := a.assertion.Verify(r, got, c); err != nil {
				a.deny(r, tier, "assertion", err)
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		a.allow(r, tier, c) // audit: user, cert_serial, action, target
		r.Body = io.NopCloser(bytes.NewReader(body))
		next(w, r.WithContext(withCert(r.Context(), c)))
	})
}
```

Send the client nothing but the status. The reason goes to the audit log, the error detail to the diagnostic log. On `sig_mismatch`, log `httpsig.BaseHash(e.Base)` from the `*httpsig.Error`, so it can be compared with the hash `mvm` prints.

### The destructive tier

A destructive request carries, as well as its signature, a passkey assertion whose challenge is SHA-256 of the request's signature base. `mvm` and web apps get it from the IdP's approval page (see [Clients](#destructive-actions)). The service checks it with `lib/assertion` against the passkey keys in the certificate:

```go
a.assertion = &assertion.Verifier{
	RPID:   "auth.jack.farm",
	Origin: "https://id.auth.jack.farm",
}
```

It checks the `webauthn.get` type, the challenge against the signature base this side rebuilt, the origin, the RP ID hash, the user-present and user-verified flags, and the signature with the passkey the credential ID names. Nothing is stored: the signature counter is ignored, and the request's own nonce stops a replay.

### Testing a service

`lib` has everything to sign test requests without an IdP: make a CA with `cert.NewCA`, issue with `CA.Issue`, sign with `httpsig.Signer`, and fix the clock with each type's `Now`. `lib/cert/cert_test.go` (`TestWithHTTPSig`) is a complete example. Two tests every service should have:

- every route has a tier (list the mux's routes and fail on any without one)
- each tier refuses a certificate with too few roles, and the destructive tier refuses a request with no assertion

## Web apps behind Caddy

For apps that know nothing about the SSO. Caddy asks `sso-proxy` about every request; `sso-proxy` keeps a cookie session per app and signs users in through the IdP.

```
browser ─▶ Caddy grafana.jack.farm ─ forward_auth ─▶ sso-proxy
                │                                      │ no session: redirect to the IdP,
                │                                      │ exchange the code on return
                └─ allowed: reverse_proxy ─▶ grafana   └ session: 200 + X-Sso-User, X-Sso-Roles
```

### Nix on the Caddy host

```nix
services.sso-proxy = {
  enable = true;
  listenAddress = "127.0.0.1:9310";
  idp = "https://id.auth.jack.farm";
  caCertificate = ./sso/ca.pem;
  apps.grafana = {
    host = "grafana.jack.farm";
    # Leave out to allow any user whose certificate names this app.
    roles = [ ];
  };
};

services.caddy.virtualHosts."grafana.jack.farm".extraConfig = ''
  # The callback and logout are served by sso-proxy itself.
  handle /.sso/* {
    reverse_proxy 127.0.0.1:9310
  }
  handle {
    forward_auth 127.0.0.1:9310 {
      uri /verify?app=grafana
      copy_headers X-Sso-User X-Sso-Roles
    }
    reverse_proxy 10.0.0.71:3000
  }
'';
```

And on the IdP, the matching client: `services.sso.clients.grafana.redirectUri = "https://grafana.jack.farm/.sso/callback";`.

`copy_headers` overwrites any `X-Sso-*` header the browser sent, so the app can trust them. Make sure the app is reachable **only** through Caddy, or anyone can send those headers directly.

### The app

Grafana takes the user from a header:

```ini
[auth.proxy]
enabled = true
header_name = X-Sso-User
header_property = username
auto_sign_up = true
headers = Groups:X-Sso-Roles
```

### How the session works

- On the first visit `sso-proxy` redirects to `https://id.auth.jack.farm/authorize?client=grafana&state=…`. If the browser already has an SSO session at the IdP, that's a silent redirect back; otherwise the user signs in with a passkey.
- The IdP redirects to `/.sso/callback?code=…`. `sso-proxy` exchanges the code with a request signed with **its own** key and certificate (the IdP issues it one for service `sso-proxy`), so the code is useless to anyone who intercepts it.
- The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, scoped to `grafana.jack.farm`, and lasts no longer than the certificate behind it. No JavaScript can read anything worth stealing.
- State-changing requests must carry an `Origin` that matches the app's host, or `sso-proxy` refuses them.

Destructive actions in a web app go through the same approval page as the CLI; the app opens it in a popup with the signature base and gets the assertion back with `postMessage` from `https://id.auth.jack.farm` only.

## Clients

### mvm

```sh
mvm login                                   # once a day; device flow, passkey on any device
mvm req GET /v1/status                      # signed GET to statusd
mvm req POST /v1/microvms/web/restart       # write: needs the write role
mvm req -d '{"vm":"web"}' POST /v1/deploy   # body is covered by Content-Digest
```

`mvm` reads the service address from `~/.config/mvm/config.toml`:

```toml
idp = "https://id.auth.jack.farm"

[services.statusd]
url = "http://farm-1.wg:9021"   # must match one of statusd's authorities exactly
```

When a request is rejected, `mvm` prints the status and the SHA-256 of the signature base it signed, for comparison with the service's log:

```
401 Unauthorized (base sha256 3f9c…e1)
```

`mvm verify base.txt` re-checks a logged signature base offline.

### Destructive actions

```sh
mvm req DELETE /v1/microvms/old
# This needs approval. Open:
#   https://id.auth.jack.farm/approve/K7PX
# Waiting…
# Approved with yubikey-5c. 204 No Content
```

`mvm` signs the request first, then posts the signature base to the IdP (a signed request too). The approval page shows the method, path and target in plain words, built from the same base it hashes, and asks for a passkey touch. `mvm` polls for the assertion and sends the request with it. The approval is good for that one request only: a different body, target or nonce changes the base, and the challenge with it.

### Your own Go program

Anything that can read the key and certificate `mvm login` wrote can sign requests:

```go
import (
	"github.com/oxgen1/sso/lib/cert"
	"github.com/oxgen1/sso/lib/httpsig"
)

key, der := loadMvmCredentials() // ~/.local/state/mvm/{key,cert}.pem
c, err := cert.Parse(der)
if err != nil {
	return err
}
signer := &httpsig.Signer{Key: key, Cert: der, KeyID: c.Serial}

body := []byte(`{"vm":"web"}`)
req, _ := http.NewRequest(http.MethodPost, "http://farm-1.wg:9021/v1/microvms/web/restart", bytes.NewReader(body))
base, err := signer.Sign(req, body)
if err != nil {
	return err
}
resp, err := http.DefaultClient.Do(req)
// On a 401, print httpsig.BaseHash(base) to compare with the service's log.
```

Sign last, after every header and the URL are final. Anything that changes the method, host, path, query or body afterwards (a redirect, a proxy rewriting paths) breaks the signature. Don't follow redirects for signed requests.

## Checklist for a new service

1. Pick a name and add it to `users.<name>.services` on the IdP for the users who need it.
2. Give the service `ca.pem`, its name, and every `host:port` clients will use.
3. Put writes on WireGuard (or a Unix socket) only.
4. Give every route a tier; add the test that fails on a route without one.
5. Log the reason code to the audit log and nothing more specific to the client.
6. Try it: `mvm login`, a read, a write, a write without the role (403), and one with an expired certificate (401, `cert_expired`).
