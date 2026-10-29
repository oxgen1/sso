# TODO

Design: [docs/design.md](docs/design.md).

- [ ] Create the public GitHub repo `oxgen1/sso` and push.
- [ ] Before deploying (milestone 3): a DNS-01 wildcard certificate for `*.auth.jack.farm`, and DNS for `id.auth.jack.farm` (LAN and WireGuard).

Logging, rate limits and tests are part of every milestone, not a phase at the end.

## 1. Library (`lib/`)

- [x] `httpsig`: RFC 8941 subset parser, signature base, `content-digest`, sign and verify with the fixed profile, reason codes as a closed set, nonce cache. Tested against RFC 9421 B.2.4 and B.3 and RFC 9530 B.1 and B.2, with one mutation test per reason, a reason-coverage test, a golden base and four fuzzers.
- [x] `cert`: issue and verify X.509 client certificates (roles, services, passkey keys, source address). `Verifier.Verify` is the `httpsig.Verifier` Cert func. 51 mutation cases, a reason-coverage test, an end-to-end test through `httpsig`, and two fuzzers (extension round trip, Verify).
- [ ] Register an IANA Private Enterprise Number and replace the placeholder `2.999.7` arc in `lib/cert/ext.go` before tagging.
- [x] `assertion`: WebAuthn assertion check for the destructive tier. `clientDataJSON` checked with the spec's limited verification (byte prefix), signature first; 49 mutation cases, a reason-coverage test, an end-to-end test through `httpsig` and `cert`, and two fuzzers (header round trip, Check with a signing authenticator).
- [ ] Tag `lib/v0.1.0`.

## 2. IdP

- [ ] `cmd/sso`:
  - [x] WebAuthn sign-in with UV required (`internal/idp`): discoverable credentials, one attempt per challenge, `Origin` checked on every POST, a rate limit per address on `begin`. 20 rejection cases through the HTTP handler with a software authenticator.
  - [x] SSO session: `__Host-sso` cookie (HttpOnly, Secure, SameSite=Strict), 8 h absolute, replaced on a new sign-in, ended by sign-out. In-memory stores (`internal/store`) and token buckets (`internal/ratelimit`), both with size limits. `sso serve`.
  - [ ] Try sign-in in a real browser once DNS and the certificate exist.
  - [x] Device flow (RFC 8628) and certificate issuance: a CSR proves the key, each approval is a passkey assertion (not the session) with the source addresses checked, one certificate per code, `slow_down`, rate limits per address. CA key from `$CREDENTIALS_DIRECTORY`.
  - [x] `sso enroll` and its page: an HMAC link (key derived from the CA key), single use, the snippet on the page and in the audit log. RP ID `localhost` with `http://localhost:PORT` for trying it on a laptop.
- [x] `internal/config`: users, roles, passkey keys and clients from the JSON the Nix module writes, all checked at load (each user's claims through `cert.Claims.Check`, credential IDs unique across users); CA key (PKCS #8) from `LoadCredential`. `sso ca init` and `sso config check` (for a build-time check in the module).
- [x] `internal/webauthn`: registration (attestation `none`, ES256 only) with strict CBOR; tested against the WebAuthn L3 §16.2 vector, 30 mutation cases and a fuzzer. `lib/assertion` gained `CheckChallenge` (sign-in) and `CheckClientData` (shared with registration).
- [x] End to end without farm (`internal/idp/e2e_test.go`): a key and CSR, the device flow with a passkey, then signed writes over a real connection to a stand-in service that trusts only the CA. Rejects a replay, another service, another CA, another key, another authority, and an expired certificate; logging in again works.
- [x] Audit log with a hash chain (`internal/audit`): one chain per run from `audit_start` to `audit_stop`, `sso audit verify` for `journalctl -o cat` output. Every IdP test checks the chain it leaves. Diagnostic log and rate limits are in place.

## 3. Nix and deployment

- [x] `packages.sso` (runs every test, lib's too), `nixosModules.sso` (`nix/module.nix`): options as in setup.md, the configuration checked at build time with `sso config check`, a hardened unit (`DynamicUser`, CA key through `LoadCredential`, only localhost may connect, exposure 0.9), and an `sso` wrapper on PATH so `sudo sso enroll jack` works.
- [x] NixOS VM test without a browser (`nix/test.nix`): the unit starts, the sign-in page and the device flow answer, enroll works for root only, the sandbox scores 1.5 or better, and the run's audit chain verifies.
- [ ] NixOS VM test with headless Chromium's virtual authenticator: enrollment, sign-in, device approval. Interop check of signatures against an independent RFC 9421 implementation.
- [ ] Deploy on its own VM over WireGuard; NTP on every host.

## 4. OIDC and the proxy

- [ ] IdP as a minimal OIDC provider (design: Browser apps): code flow with PKCE, discovery, JWKS, ES256 ID token with `auth_time`, `/userinfo` with a 5-minute access token, clients and secrets from the configuration, its own ID-token key. Interop test with a maintained client library.
- [ ] A CSR with the token request returns a certificate (`not_before` = `auth_time`), for app servers that call APIs as the user.
- [ ] `cmd/sso-proxy` as an OIDC client: `forward_auth`, cookie sessions ending at `auth_time + 8h`, Origin check, `state` and `nonce`.
- [ ] Later, when an app needs it: `max_age` and `prompt=login`, for a middle tier; an RS256 ID-token key.

## 5. statusd and farm

- [ ] `farm` in its own repo (~/Dev/farm, Go, importing only `lib`): remote status and light management for microvms and slimdeploy previews. `farm login`, `farm req`, and `farm verify` (replays a logged signature base). `mvm`, the Rust tool on the host, is unrelated and stays local.
- [ ] statusd `internal/auth` middleware and route tiers (tracked in server-api's TODO.md).

## 6. Destructive tier

- [ ] IdP approval page that shows the action and runs WebAuthn get over the signature-base hash.
- [ ] Assertion headers from farm and web apps; checked in statusd.

## Later

- [ ] CA rotation: instructions and tooling.
- [ ] Client keys on a YubiKey or TPM.
