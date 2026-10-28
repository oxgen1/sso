// Package httpsig signs and verifies requests with RFC 9421 HTTP Message
// Signatures, using one fixed profile (see profile.go and docs/design.md). The
// mvm CLI signs with Signer and statusd verifies with Verifier, so it may
// import only the standard library (enforced by depguard in .golangci.yml at
// the repo root).
//
// Verify fails with an *Error whose Reason comes from a closed set (see
// Reasons). Log the reason in the audit log and Err in the diagnostic log;
// send the client nothing more specific than the HTTP status.
package httpsig
