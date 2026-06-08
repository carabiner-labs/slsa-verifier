// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/signer/key"
)

// ErrSignatureRequired is returned by VerifySignatures when the
// envelope is unsigned and SignatureOptions.Required is true. It is
// a verification outcome rather than an execution error — callers
// should translate it to their domain's "verification failed" exit
// path (e.g. exit code 1) rather than treating it as a setup
// problem.
var ErrSignatureRequired = errors.New("envelope is unsigned and signatures are required")

// SignatureOptions parameterizes VerifySignatures. Keys are passed
// to the envelope's Verify implementation; Required toggles the
// "unsigned → error" policy independent of any keys.
type SignatureOptions struct {
	// Keys is the set of public-key providers used to verify DSSE
	// signatures on the envelope. Sigstore bundles verify against an
	// embedded trust root regardless and do not require entries here.
	Keys []key.PublicKeyProvider

	// Required, when true, makes VerifySignatures return
	// ErrSignatureRequired if the envelope carries zero signatures.
	// Use this to enforce a "must be signed" policy independent of
	// what Keys were supplied.
	Required bool
}

// VerifySignatures runs the envelope's cryptographic signature
// verification and, when opts.Required is set, also enforces that
// the envelope is signed at all. The two checks are kept in one
// method because callers nearly always want both: confirming the
// signatures that are present are valid, and confirming there is
// at least one of them when policy demands it.
//
// Returns ErrSignatureRequired when the envelope is unsigned and
// opts.Required is true. Other errors come from the envelope's
// Verify implementation (typically signature/key mismatches, or
// trust-root failures for Sigstore bundles).
func (*Verifier) VerifySignatures(env Envelope, opts SignatureOptions) error {
	if env == nil {
		return errors.New("nil envelope")
	}
	if err := env.Verify(opts.Keys); err != nil {
		return fmt.Errorf("verifying envelope signatures: %w", err)
	}
	if opts.Required && len(env.GetSignatures()) == 0 {
		return ErrSignatureRequired
	}
	return nil
}
