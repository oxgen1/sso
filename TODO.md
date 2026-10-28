# TODO

Design: [docs/design.md](docs/design.md).

- [ ] Create the public GitHub repo `oxgen1/sso` and push.
- [ ] Before milestone 2: a DNS-01 wildcard certificate for `*.auth.jack.farm`, and DNS for `id.auth.jack.farm` (LAN and WireGuard).

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
  - device flow (RFC 8628)
  - certificate issuance
  - `sso enroll`
- [x] `internal/config`: users, roles, passkey keys and clients from the JSON the Nix module writes, all checked at load (each user's claims through `cert.Claims.Check`, credential IDs unique across users); CA key (PKCS #8) from `LoadCredential`. `sso ca init` and `sso config check` (for a build-time check in the module).
- [x] `internal/webauthn`: registration (attestation `none`, ES256 only) with strict CBOR; tested against the WebAuthn L3 §16.2 vector, 30 mutation cases and a fuzzer. `lib/assertion` gained `CheckChallenge` (sign-in) and `CheckClientData` (shared with registration).
- [ ] Audit log with a hash chain; diagnostic log; rate limits.

## 3. statusd and mvm

- [ ] `mvm login`, `mvm req`, and `mvm verify` (replays a logged signature base).
- [ ] statusd `internal/auth` middleware and route tiers (tracked in server-api's TODO.md).

## 4. Destructive tier

- [ ] IdP approval page that shows the action and runs WebAuthn get over the signature-base hash.
- [ ] Assertion headers from mvm and web apps; checked in statusd.

## 5. Proxy

- [ ] `cmd/sso-proxy`: `forward_auth`, code exchange, cookie sessions, Origin check.

## 6. Nix

- [ ] `packages.sso`, `nixosModules.sso`, hardened units (as with statusd).
- [ ] NixOS VM test: software authenticator, end-to-end flows, interop check of signatures against an independent RFC 9421 implementation.
- [ ] Deploy on its own VM over WireGuard; NTP on every host.

## Later

- [ ] CA rotation: instructions and tooling.
- [ ] Client keys on a YubiKey or TPM.
