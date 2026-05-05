// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
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
// to every Verify call unless overridden by per-call VerificationOptions.
func WithDefaultVerificationOptions(o VerificationOptions) Option {
	return func(v *Verifier) error {
		v.defaultVerificationOptions = o
		return nil
	}
}

// VerificationOptions holds per-call settings for Verifier.Verify.
type VerificationOptions struct {
	// RunBuildTypeControls toggles execution of custom buildType controls.
	RunBuildTypeControls bool

	// RunUserControls toggles execution of user-supplied controls.
	RunUserControls bool

	// UserControls is the list of user-supplied controls evaluated when
	// RunUserControls is true.
	UserControls []*controls.Control

	// Params is the parameter map exposed to CEL expressions as `params`.
	// Values are typically string or []string, matching what the --param
	// CLI flag produces.
	Params map[string]any
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
