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

// ErrSignatureUnverified is returned by VerifySignatures when the
// envelope carries signatures but, after Verify, exposes no
// verification result marked as verified. That happens when no key
// or trust material was supplied to check the signatures against,
// or when the material was supplied and none of the signatures
// matched. Like ErrSignatureRequired it is a verification outcome,
// not an execution error.
var ErrSignatureUnverified = errors.New("envelope is signed but its signature was not verified and signatures are required")

// SignatureOptions parameterizes VerifySignatures. Keys are passed
// to the envelope's Verify implementation; Required toggles the
// "unsigned → error" policy independent of any keys.
type SignatureOptions struct {
	// Keys is the set of public-key providers used to verify DSSE
	// signatures on the envelope. Sigstore bundles verify against an
	// embedded trust root regardless and do not require entries here.
	Keys []key.PublicKeyProvider

	// Required, when true, makes VerifySignatures return
	// ErrSignatureRequired if the envelope carries zero signatures,
	// and ErrSignatureUnverified if it carries signatures that did
	// not produce a verified result. Use this to enforce a "must be
	// signed and verified" policy.
	Required bool
}

// VerifySignatures runs the envelope's cryptographic signature
// verification and, when opts.Required is set, also enforces that
// the envelope is signed and that the signature verified. The checks
// are kept in one method because callers nearly always want both:
// running verification on whatever signatures are present, and
// demanding a verified signature when policy requires it.
//
// A missing signal is not an error on its own: an unsigned envelope,
// or a signed one with no key material to check it against, passes
// when opts.Required is false. Errors from the envelope's Verify
// implementation (signature/key mismatches, trust-root failures for
// Sigstore bundles) always propagate.
//
// With opts.Required set, returns ErrSignatureRequired when the
// envelope carries no signatures, and ErrSignatureUnverified when it
// carries signatures but GetVerification reports no verified result.
// The verdict is read from the envelope's Verification rather than
// from the presence of signatures because envelope implementations
// may record a failed verification as a result instead of returning
// an error from Verify.
func (*Verifier) VerifySignatures(env Envelope, opts SignatureOptions) error {
	if env == nil {
		return errors.New("nil envelope")
	}
	if err := env.Verify(opts.Keys); err != nil {
		return fmt.Errorf("verifying envelope signatures: %w", err)
	}
	if !opts.Required {
		return nil
	}
	if len(env.GetSignatures()) == 0 {
		return ErrSignatureRequired
	}
	if v := env.GetVerification(); v == nil || !v.GetVerified() {
		return ErrSignatureUnverified
	}
	return nil
}
