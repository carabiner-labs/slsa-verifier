// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"context"
	"fmt"

	"github.com/carabiner-dev/attestation"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/controls"
	// Imported for its init: registers the SLSA-only predicate parsers as
	// the collector's global registry so envelope/statement parsing only
	// recognises SLSA build and source predicate types.
	_ "github.com/carabiner-labs/slsa-verifier/pkg/slsa/predicate"
)

// Verifier is the SLSA attestation verifier. It orchestrates the layered
// verification flow described in the project design, delegating the
// per-layer logic to the configured verifierImplementation.
type Verifier struct {
	impl                       VerifierImplementation
	Options                    Options
	defaultVerificationOptions VerificationOptions
}

// New constructs a Verifier with the embedded control catalog and the
// default verifierImplementation. Pass options to override either.
func New(opts ...Option) (*Verifier, error) {
	impl, err := newDefaultImplementation()
	if err != nil {
		return nil, fmt.Errorf("constructing default implementation: %w", err)
	}
	v := &Verifier{
		impl:                       impl,
		Options:                    DefaultOptions(),
		defaultVerificationOptions: DefaultVerificationOptions(),
	}
	for _, fn := range opts {
		if err := fn(v); err != nil {
			return nil, fmt.Errorf("applying option: %w", err)
		}
	}
	if v.Options.Catalog == nil {
		cat, err := controls.LoadEmbedded()
		if err != nil {
			return nil, fmt.Errorf("loading embedded catalog: %w", err)
		}
		v.Options.Catalog = cat
	}
	return v, nil
}

// Verify runs the layered verification flow against the given statement
// and returns a Result describing the outcome.
func (v *Verifier) Verify(ctx context.Context, statement attestation.Statement, opts ...VerificationOption) (*Result, error) {
	if statement == nil {
		return nil, fmt.Errorf("statement is required")
	}

	vopts := v.defaultVerificationOptions
	for _, fn := range opts {
		if err := fn(&vopts); err != nil {
			return nil, fmt.Errorf("applying verification option: %w", err)
		}
	}

	// Layer 1: signature verification.
	if err := v.impl.VerifySignatures(ctx, &vopts, statement); err != nil {
		return nil, fmt.Errorf("verifying signatures: %w", err)
	}

	// Layer 2: identity check.
	if err := v.impl.CheckIdentities(ctx, &vopts, statement); err != nil {
		return nil, fmt.Errorf("checking identities: %w", err)
	}

	// Layer 3: predicate routing (build vs source).
	category, err := v.impl.ResolveCategory(&vopts, v.Options.Catalog, statement)
	if err != nil {
		return nil, fmt.Errorf("resolving predicate category: %w", err)
	}

	// Layer 4: select and run core SLSA controls.
	coreCtrls := v.impl.SelectCoreControls(&vopts, v.Options.Catalog, category)
	coreResults, err := v.impl.RunControls(ctx, &vopts, coreCtrls, statement)
	if err != nil {
		return nil, fmt.Errorf("running core controls: %w", err)
	}

	// Layer 5: select and run buildType controls (optional).
	var buildTypeResults []*ControlResult
	if vopts.RunBuildTypeControls {
		btCtrls := v.impl.SelectBuildTypeControls(&vopts, v.Options.Catalog, statement)
		buildTypeResults, err = v.impl.RunControls(ctx, &vopts, btCtrls, statement)
		if err != nil {
			return nil, fmt.Errorf("running buildType controls: %w", err)
		}
	}

	// Layer 6: select and run user controls (optional).
	var userResults []*ControlResult
	if vopts.RunUserControls {
		userCtrls := v.impl.SelectUserControls(&vopts)
		userResults, err = v.impl.RunControls(ctx, &vopts, userCtrls, statement)
		if err != nil {
			return nil, fmt.Errorf("running user controls: %w", err)
		}
	}

	// Layer 7: compute the final result.
	result, err := v.impl.ComputeResult(&vopts, coreResults, buildTypeResults, userResults)
	if err != nil {
		return nil, fmt.Errorf("computing result: %w", err)
	}
	return result, nil
}
