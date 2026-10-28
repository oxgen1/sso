// Package assertion checks the passkey assertion that a destructive request
// carries as well as its signature (docs/design.md, "Destructive-action
// approval"). The IdP's approval page runs WebAuthn get with the challenge set
// to SHA-256 of the request's signature base (Challenge); the client sends the
// result in the Sso-Assertion header; the service checks it with Verify
// against the passkey keys in the request's certificate.
//
// Nothing is stored. The signature counter is ignored (synced passkeys report
// 0), and the request's own nonce stops a replay, since a different nonce
// changes the base and the challenge with it.
//
// Verify fails with an *Error whose Reason comes from a closed set (see
// Reasons), as httpsig does. Like httpsig and cert, the package may import
// only the standard library and the rest of lib.
package assertion
