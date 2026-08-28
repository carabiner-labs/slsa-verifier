// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"context"
	"fmt"
	"maps"

	"github.com/carabiner-dev/attestation"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/controls"
	// Imported for its init: registers the SLSA-only predicate parsers as
	// the collector's global registry so envelope/statement parsing only
	// recognises SLSA build and source predicate types.
	_ "github.com/carabiner-labs/slsa-verifier/pkg/slsa/predicate"
	"github.com/carabiner-labs/slsa-verifier/pkg/subject"
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
	// The struct copy above still shares the default Params map; clone it
	// so WithParam calls don't leak into subsequent Verify calls.
	vopts.Params = maps.Clone(vopts.Params)
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

	// Layer 2b: bind the statement to the artifacts the caller holds.
	// A mismatch is a verdict, not an error: the controls still run so
	// the caller sees the full picture, and the result fails below.
	subjects, err := v.impl.CheckSubjects(ctx, &vopts, statement)
	if err != nil {
		return nil, fmt.Errorf("checking subjects: %w", err)
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
		// A buildType the catalog knows, with no expectation stated for
		// it, is an incomplete invocation rather than a pass.
		run, skipped, err := partitionBuildTypeControls(&vopts, btCtrls, statement)
		if err != nil {
			return nil, err
		}
		buildTypeResults, err = v.impl.RunControls(ctx, &vopts, run, statement)
		if err != nil {
			return nil, fmt.Errorf("running buildType controls: %w", err)
		}
		buildTypeResults = append(buildTypeResults, skipped...)
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
	if result != nil {
		// Record the spec version the core category resolved to so
		// callers (and emitted VSAs) can state which criteria applied.
		result.SpecVersion = controls.SpecVersionOf(category)
		result.Subjects = subjects
		if !subject.AllMatched(subjects) {
			result.Status = StatusFail
			result.Message = joinMessages(result.Message, subjectsMessage(subjects))
		}
	}
	return result, nil
}

// subjectsMessage summarizes which expected subjects the statement is
// not about.
func subjectsMessage(matches []subject.Match) string {
	unmatched := 0
	for _, m := range matches {
		if !m.Matched {
			unmatched++
		}
	}
	return fmt.Sprintf("%d of %d expected subjects not found in the attestation", unmatched, len(matches))
}

func joinMessages(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}
