// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	sapi "github.com/carabiner-dev/signer/api/v1"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/controls"
)

// Options holds construction-time settings for a Verifier.
type Options struct {
	// Catalog is the set of controls available to the verifier. When nil,
	// the verifier loads the embedded catalog at construction time.
	Catalog *controls.Catalog
}

// DefaultOptions returns a zero-value Options struct used when no options
// are provided to New.
func DefaultOptions() Options {
	return Options{}
}

// Option is a functional option applied at Verifier construction time.
type Option func(*Verifier) error

// WithCatalog sets the control catalog the verifier will use, replacing
// the embedded one.
func WithCatalog(c *controls.Catalog) Option {
	return func(v *Verifier) error {
		v.Options.Catalog = c
		return nil
	}
}

// WithImplementation overrides the verifier implementation. Primarily
// used in tests to inject a counterfeiter-generated fake.
func WithImplementation(impl VerifierImplementation) Option {
	return func(v *Verifier) error {
		v.impl = impl
		return nil
	}
}

// WithDefaultVerificationOptions sets the verification options that apply
// to every Verify call unless overridden by the iptions.
func WithDefaultVerificationOptions(o *VerificationOptions) Option {
	return func(v *Verifier) error {
		if o != nil {
			v.defaultVerificationOptions = *o
		}
		return nil
	}
}

// VerificationOptions holds per-call settings for Verifier.Verify.
type VerificationOptions struct {
	// RunBuildTypeControls toggles execution of custom buildType controls.
	RunBuildTypeControls bool

	// RunUserControls toggles execution of user supplied controls.
	RunUserControls bool

	// RequireSignatures, when true, fails verification if the statement
	// does not carry a verified signature (ie loaded as a plain in-toto envelope
	// or failed to verify).
	RequireSignatures bool

	// UserControls is the list of user-supplied controls evaluated when
	// RunUserControls is true.
	UserControls []*controls.Control

	// ExpectedSigners is the set of identities alloed to sign the statement.
	// When set, CheckIdentities will only accept the statement if at
	// least one verified signer matches one of these (OR'ed). An empty list
	// is the default and skips identity matching.
	ExpectedSigners []*sapi.Identity

	// ForceTrack overrides the catalog's predicate-type to track
	// resolution. Empty means "auto" (the catalog must associate the
	// predicate type with exactly one track). When set to a track
	// constant (TrackBuild/TrackSource), the verifier evaluates
	// against that track and errors if the catalog does not classify the
	// predicate type under it.
	ForceTrack controls.Track

	// Params is the parameter map exposed to CEL expressions as `params`.
	// Values are typically string or []string, matching what the --param
	// CLI flag produces.
	Params map[string]any

	// VerifierID identifies the entity performing the verification. It is
	// recorded on the Result and surfaces as verifier.id when a VSA is
	// emitted from the outcome. The CLI sets it to the slsa-verifier
	// project URL; consumer applications embedding the verifier should set
	// their own identity. Empty by default.
	VerifierID string

	// SpecVersion selects the SLSA spec version whose verification
	// criteria (control catalog) the statement is evaluated against,
	// eg "1.2". Criteria carry forward across releases, so the newest
	// catalog at or below the requested version applies. Empty (the
	// default) means the latest version the catalog defines for the
	// resolved track.
	SpecVersion string

	// MinLevel is the SLSA level the attestation is required to reach.
	// When set (> 0), core controls declared above it are informative:
	// their failure caps the computed level but does not fail the run.
	// Zero (the default) keeps the strict semantics where every
	// applicable control must pass. Controls without a declared level,
	// buildType controls and user controls are always required.
	MinLevel int
}

// DefaultVerificationOptions returns the default per-call options.
func DefaultVerificationOptions() VerificationOptions {
	return VerificationOptions{
		RunBuildTypeControls: true,
		RunUserControls:      true,
		Params:               map[string]any{},
	}
}

// VerificationOption is a functional option applied to a Verify call.
type VerificationOption func(*VerificationOptions) error

// WithBuildTypeControls toggles evaluation of custom buildType controls.
func WithBuildTypeControls(enabled bool) VerificationOption {
	return func(o *VerificationOptions) error {
		o.RunBuildTypeControls = enabled
		return nil
	}
}

// WithUserControls toggles evaluation of user-supplied controls.
func WithUserControls(enabled bool) VerificationOption {
	return func(o *VerificationOptions) error {
		o.RunUserControls = enabled
		return nil
	}
}

// WithRequireSignatures toggles whether the verifier fails when the
// statement is unsigned or its signature did not verify.
func WithRequireSignatures(required bool) VerificationOption {
	return func(o *VerificationOptions) error {
		o.RequireSignatures = required
		return nil
	}
}

// WithExpectedSigner appends an expected signer identity. Calling this
// option multiple times accumulates entries (OR 'ed).
func WithExpectedSigner(id *sapi.Identity) VerificationOption {
	return func(o *VerificationOptions) error {
		if id == nil {
			return nil
		}
		o.ExpectedSigners = append(o.ExpectedSigners, id)
		return nil
	}
}

// WithExpectedSigners replaces the expected signer list with ids.
func WithExpectedSigners(ids []*sapi.Identity) VerificationOption {
	return func(o *VerificationOptions) error {
		o.ExpectedSigners = ids
		return nil
	}
}

// WithTrack forces the verifier to evaluate the statement against the
// given track regardless of how the catalog classifies the predicate
// type. The empty value means "auto" and falls back to catalog-driven
// resolution. Pass controls.TrackBuild or controls.TrackSource (or any
// future track) explicitly.
func WithTrack(track controls.Track) VerificationOption {
	return func(o *VerificationOptions) error {
		o.ForceTrack = track
		return nil
	}
}

// WithUserControlList sets the list of user-supplied controls to evaluate.
func WithUserControlList(list []*controls.Control) VerificationOption {
	return func(o *VerificationOptions) error {
		o.UserControls = list
		return nil
	}
}

// WithParam sets a single parameter on the params map exposed to CEL.
// Calling WithParam multiple times accumulates entries.
func WithParam(name string, value any) VerificationOption {
	return func(o *VerificationOptions) error {
		if o.Params == nil {
			o.Params = map[string]any{}
		}
		o.Params[name] = value
		return nil
	}
}

// WithParams replaces the params map with the provided one.
func WithParams(params map[string]any) VerificationOption {
	return func(o *VerificationOptions) error {
		o.Params = params
		return nil
	}
}

// WithSpecVersion selects the SLSA spec version whose verification
// criteria the statement is evaluated against (e.g. "1.2" or "v1.2").
// The newest catalog at or below the requested version applies. An
// empty string (default) selects the latest available.
func WithSpecVersion(version string) VerificationOption {
	return func(o *VerificationOptions) error {
		o.SpecVersion = version
		return nil
	}
}

// WithMinLevel sets the SLSA level the attestation must reach for the
// verification to pass. Core controls declared above the minimum level
// become informative: when they fail they cap the computed SLSA level
// without failing the run. Zero (the default) requires every applicable
// control to pass regardless of level.
func WithMinLevel(level int) VerificationOption {
	return func(o *VerificationOptions) error {
		o.MinLevel = level
		return nil
	}
}

// WithVerifierID sets the identity of the entity performing the
// verification. It is recorded on the Result and used as verifier.id when
// a VSA is emitted. Consumer applications embedding the verifier should
// set their own identity here, the CLI sets the slsa-verifier project URL.
func WithVerifierID(id string) VerificationOption {
	return func(o *VerificationOptions) error {
		o.VerifierID = id
		return nil
	}
}
