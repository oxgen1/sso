package assertion

import (
	"errors"
	"fmt"
	"slices"
)

// Reason says why an assertion was rejected. The set is closed, and every
// value starts with "assertion_" so the audit log can't confuse one with an
// httpsig reason.
type Reason string

const (
	// No Sso-Assertion header.
	ReasonMissing Reason = "assertion_missing"
	// The header or authenticatorData doesn't parse.
	ReasonMalformed Reason = "assertion_malformed"
	// The credential ID isn't one of the certificate's passkeys.
	ReasonCredential  Reason = "assertion_credential"
	ReasonSigMismatch Reason = "assertion_sig_mismatch"
	// rpIdHash isn't SHA-256 of the RP ID.
	ReasonRP Reason = "assertion_rp"
	// UP or UV is clear, or attested credential data or extensions are present.
	ReasonFlags Reason = "assertion_flags"
	// clientDataJSON.type isn't webauthn.get.
	ReasonType Reason = "assertion_type"
	// The passkey approved a different request.
	ReasonChallenge Reason = "assertion_challenge"
	// Made on a page other than the IdP's, or in a cross-origin iframe.
	ReasonOrigin Reason = "assertion_origin"
)

var reasons = []Reason{
	ReasonMissing, ReasonMalformed, ReasonCredential, ReasonSigMismatch,
	ReasonRP, ReasonFlags, ReasonType, ReasonChallenge, ReasonOrigin,
}

// Reasons lists every reason Verify can return.
func Reasons() []Reason { return slices.Clone(reasons) }

// Error is a rejected assertion: Reason for the audit log, Err for the
// diagnostic log.
type Error struct {
	Reason Reason
	Err    error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return "assertion: " + string(e.Reason)
	}
	return fmt.Sprintf("assertion: %s: %v", e.Reason, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// ReasonOf returns the reason in err, or "" if err isn't from Verify.
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

func fail(r Reason, format string, a ...any) *Error {
	return &Error{Reason: r, Err: fmt.Errorf(format, a...)}
}
