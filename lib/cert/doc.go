// Package cert will define the short-lived client certificate the IdP issues:
// user, roles, client public key, passkey public keys, expiry, and an optional
// source-address restriction. Services verify it against the CA public key
// alone. Shared with statusd, so standard library only.
package cert
