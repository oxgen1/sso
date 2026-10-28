package httpsig

import (
	"errors"
	"fmt"
	"slices"
)

// Reason says why a request was rejected. The set is closed: Verify returns
// only these, so each one can be counted, alerted on and tested on its own.
type Reason string

const (
	// A signature header is missing, repeated, too long or outside the RFC 8941
	// subset, or a covered component can't be put in the signature base.
	ReasonMalformed Reason = "malformed"
	// Well-formed, but not the fixed profile: label, components, parameters.
	ReasonProfile Reason = "profile"
	// created is older than the skew allows, or expires has passed.
	ReasonExpired Reason = "expired"
	// created is further in the future than the skew allows.
	ReasonNotYetValid Reason = "not_yet_valid"
	// created is from before this service started (write routes only).
	ReasonBeforeStart Reason = "before_start"
	ReasonTag         Reason = "tag"
	// @authority isn't one of this service's names.
	ReasonAuthority Reason = "authority"
	// The certificate doesn't chain to the CA, or keyid isn't its serial.
	ReasonCert        Reason = "cert"
	ReasonCertExpired Reason = "cert_expired"
	// The certificate isn't valid for this service or source address.
	ReasonScope       Reason = "scope"
	ReasonDigest      Reason = "digest"
	ReasonSigMismatch Reason = "sig_mismatch"
	ReasonReplay      Reason = "replay"
	// The nonce cache is full of live entries, so writes are refused.
	ReasonNonceFull Reason = "nonce_full"
)

var reasons = []Reason{
	ReasonMalformed, ReasonProfile, ReasonExpired, ReasonNotYetValid,
	ReasonBeforeStart, ReasonTag, ReasonAuthority, ReasonCert,
	ReasonCertExpired, ReasonScope, ReasonDigest, ReasonSigMismatch,
	ReasonReplay, ReasonNonceFull,
}

// Reasons lists every reason Verify can return.
func Reasons() []Reason { return slices.Clone(reasons) }

// certReasons are the ones a Verifier's Cert func may return.
var certReasons = []Reason{ReasonCert, ReasonCertExpired, ReasonScope}

// Error is what Verify returns. Err is detail for the diagnostic log and is
// never sent to the client.
type Error struct {
	Reason Reason
	Err    error
	// Base is the signature base this side rebuilt, set for ReasonSigMismatch.
	// Log its SHA-256 by default (see BaseHash); the full base only under a
	// debug flag, since it holds the request's path and query.
	Base []byte
}

func (e *Error) Error() string {
	if e.Err == nil {
		return "httpsig: " + string(e.Reason)
	}
	return fmt.Sprintf("httpsig: %s: %v", e.Reason, e.Err)
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
