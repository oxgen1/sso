# sso

Single sign-on for the farm-1 homelab. It has four parts:
- a passkey authenticator
- an IdP that issues short-lived client certificates
- an auth proxy for web apps
- a small shared library (`lib/`: `httpsig`, `cert` and `assertion`, a separate Go module) that clients use to sign requests and services use to verify them

Built so far: the whole of `lib` (`httpsig`, `cert`, `assertion`); it waits only on the IANA PEN to be tagged. Progress is in [TODO.md](TODO.md).

- [docs/setup.md](docs/setup.md): running the IdP, with two example deployments
- [docs/integration.md](docs/integration.md): putting services, web apps and clients behind it
- [docs/design.md](docs/design.md): the design and why

statusd in `~/Dev/server-api` is the first consumer.

## Development

Needs Nix with flakes. The dev shell provides Go, gopls, delve, golangci-lint and govulncheck.

```sh
direnv allow          # or: nix develop

go test ./... && (cd lib && go test ./...)
golangci-lint run ./... && (cd lib && golangci-lint run ./...)  # gosec + depguard
govulncheck ./...
```
