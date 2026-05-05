// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package slsa

import (
	"context"
	"errors"

	"github.com/carabiner-dev/attestation"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/controls"
)

// ErrNotImplemented is returned by stub implementation methods until a
// later phase fills them in.
var ErrNotImplemented = errors.New("slsa: not implemented")

// VerifierImplementation is the contract Verifier delegates to. It maps
// the verification layers described in the project design (signature,
// identity, predicate routing, control selection, control evaluation,
// result computation) onto discrete, independently testable methods.
//
// A counterfeiter-generated fake of this interface lives in the
// slsafakes sub-package and is injected via WithImplementation.
//
//counterfeiter:generate . VerifierImplementation
type VerifierImplementation interface {
	// VerifySignatures verifies the integrity of the statement's envelope
	// (layer 1).
	VerifySignatures(ctx context.Context, opts *VerificationOptions, statement attestation.Statement) error

	// CheckIdentities matches the verified identities against the expected
	// signer identities (layer 2). Currently a placeholder; identity-match
	// flags will be added later.
	CheckIdentities(ctx context.Context, opts *VerificationOptions, statement attestation.Statement) error

	// ResolveCategory selects which catalog category to apply based on the
	// statement's predicate type (layer 3 — split build vs source).
	ResolveCategory(statement attestation.Statement) (controls.Category, error)

	// SelectCoreControls chooses the core SLSA controls to evaluate from
	// the catalog given the resolved category (layer 4).
	SelectCoreControls(opts *VerificationOptions, catalog *controls.Catalog, category controls.Category) []*controls.Control

	// SelectBuildTypeControls chooses the custom buildType controls
	// applicable to the given statement (layer 5).
	SelectBuildTypeControls(opts *VerificationOptions, catalog *controls.Catalog, statement attestation.Statement) []*controls.Control

	// SelectUserControls returns the user-supplied controls (layer 6).
	SelectUserControls(opts *VerificationOptions) []*controls.Control

	// RunControls evaluates a list of controls against the statement and
	// returns one result per control.
	RunControls(ctx context.Context, opts *VerificationOptions, ctrls []*controls.Control, statement attestation.Statement) ([]*ControlResult, error)

	// ComputeResult condenses the per-layer outcomes into the final
	// verification result, including the SLSA level (layer 7).
	ComputeResult(opts *VerificationOptions, coreResults, buildTypeResults, userResults []*ControlResult) (*Result, error)
}

// defaultImplementation is the production verifierImplementation. Each
// method is a stub returning empty results until later phases land the
// real signing, CEL, and result-computation logic.
type defaultImplementation struct{}

func (*defaultImplementation) VerifySignatures(_ context.Context, _ *VerificationOptions, _ attestation.Statement) error {
	return ErrNotImplemented
}

func (*defaultImplementation) CheckIdentities(_ context.Context, _ *VerificationOptions, _ attestation.Statement) error {
	return ErrNotImplemented
}

func (*defaultImplementation) ResolveCategory(_ attestation.Statement) (controls.Category, error) {
	return "", ErrNotImplemented
}

func (*defaultImplementation) SelectCoreControls(_ *VerificationOptions, catalog *controls.Catalog, category controls.Category) []*controls.Control {
	return catalog.Get(category)
}

func (*defaultImplementation) SelectBuildTypeControls(_ *VerificationOptions, catalog *controls.Catalog, _ attestation.Statement) []*controls.Control {
	return catalog.Get(controls.BuildType)
}

func (*defaultImplementation) SelectUserControls(opts *VerificationOptions) []*controls.Control {
	return opts.UserControls
}

func (*defaultImplementation) RunControls(_ context.Context, _ *VerificationOptions, _ []*controls.Control, _ attestation.Statement) ([]*ControlResult, error) {
	return nil, ErrNotImplemented
}

func (*defaultImplementation) ComputeResult(_ *VerificationOptions, _, _, _ []*ControlResult) (*Result, error) {
	return nil, ErrNotImplemented
}
