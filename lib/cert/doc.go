// Package cert issues and verifies the short-lived client certificates the IdP
// hands out (docs/design.md, "Protocol profile"). A certificate carries the
// user, the client public key, the services it's valid for, roles, passkey
// public keys and an optional source-address restriction, and lasts at most
// Lifetime.
//
// The IdP issues with CA.Issue. Services verify with Verifier, whose Verify
// method is an httpsig.Verifier's Cert func, against the CA certificate alone:
// no system roots, no intermediates, no online check.
//
// Only the profile Issue produces is accepted. A certificate with any other
// algorithm, extension, name form or encoding is rejected, even when its
// signature is good. Shared with statusd and mvm, so standard library only.
package cert
