# sso

Single sign-on for the farm-1 homelab. It has four parts:
- a passkey authenticator
- an IdP that issues short-lived client certificates
- an auth proxy for web apps
- a small shared library (`lib/`: `httpsig` and `cert`, a separate Go module) that clients use to sign requests and services use to verify them

Nothing is implemented yet. See [docs/design.md](docs/design.md) and [TODO.md](TODO.md).

statusd in `~/Dev/server-api` is the first consumer.

## Development

Needs Nix with flakes. The dev shell provides Go, gopls, delve, golangci-lint and govulncheck.

```sh
direnv allow          # or: nix develop

go test ./... && (cd lib && go test ./...)
golangci-lint run ./... && (cd lib && golangci-lint run ./...)  # gosec + depguard
govulncheck ./...
```
