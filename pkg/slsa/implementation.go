// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package slsa

import (
	"context"
	"errors"
	"fmt"

	"github.com/carabiner-dev/attestation"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/proto"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/controls"
	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/eval"
)

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

// defaultImplementation is the production VerifierImplementation.
// Predicate routing and control evaluation are wired to the
// registry and CEL evaluator in the eval package.
type defaultImplementation struct {
	evaluator *eval.Evaluator
}

// newDefaultImplementation constructs a defaultImplementation with a
// fresh CEL evaluator.
func newDefaultImplementation() (*defaultImplementation, error) {
	ev, err := eval.NewEvaluator()
	if err != nil {
		return nil, fmt.Errorf("building CEL evaluator: %w", err)
	}
	return &defaultImplementation{evaluator: ev}, nil
}

func (*defaultImplementation) VerifySignatures(_ context.Context, _ *VerificationOptions, _ attestation.Statement) error {
	return ErrNotImplemented
}

func (*defaultImplementation) CheckIdentities(_ context.Context, _ *VerificationOptions, _ attestation.Statement) error {
	return ErrNotImplemented
}

// ResolveCategory routes the statement to a catalog category based on
// its predicate-type URI: build provenance (any version) → BuildCore;
// SLSA source provenance → SourceCore.
func (*defaultImplementation) ResolveCategory(stmt attestation.Statement) (controls.Category, error) {
	pt := string(stmt.GetPredicateType())
	switch pt {
	case eval.PredicateProvenanceV01, eval.PredicateProvenanceV02, eval.PredicateProvenanceV1:
		return controls.BuildCore, nil
	case eval.PredicateSourceProvenance:
		return controls.SourceCore, nil
	default:
		return "", fmt.Errorf("unsupported predicate type %q", pt)
	}
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

// RunControls evaluates each control's check whose predicateType matches
// the statement's. Controls without a matching check are skipped.
func (d *defaultImplementation) RunControls(_ context.Context, opts *VerificationOptions, ctrls []*controls.Control, statement attestation.Statement) ([]*ControlResult, error) {
	pt := string(statement.GetPredicateType())

	predicate, err := extractPredicate(statement)
	if err != nil {
		return nil, fmt.Errorf("extracting predicate from statement: %w", err)
	}
	subjects := convertSubjects(statement.GetSubjects())

	results := make([]*ControlResult, 0, len(ctrls))
	for _, c := range ctrls {
		if r := d.evaluateControl(c, pt, predicate, subjects, opts.Params); r != nil {
			results = append(results, r)
		}
	}
	return results, nil
}

// evaluateControl runs the first check in the control whose predicate
// type matches pt. Returns nil when no check applies, signalling the
// caller to skip this control.
func (d *defaultImplementation) evaluateControl(
	c *controls.Control,
	predicateType string,
	predicate proto.Message,
	subjects []*intoto.ResourceDescriptor,
	params map[string]any,
) *ControlResult {
	var match *controls.Check
	for i := range c.Checks {
		if c.Checks[i].PredicateType == predicateType {
			match = &c.Checks[i]
			break
		}
	}
	if match == nil {
		return nil
	}

	cr := &ControlResult{ID: c.ID, Title: c.Title}
	for _, p := range match.Parameters {
		if _, ok := params[p]; !ok {
			cr.Status = StatusError
			cr.Message = fmt.Sprintf("missing required param %q", p)
			return cr
		}
	}

	pass, err := d.evaluator.Evaluate(predicateType, match.Expression, predicate, subjects, params)
	switch {
	case err != nil:
		cr.Status = StatusError
		cr.Message = err.Error()
	case pass:
		cr.Status = StatusPass
	default:
		cr.Status = StatusFail
	}
	return cr
}

func (*defaultImplementation) ComputeResult(_ *VerificationOptions, _, _, _ []*ControlResult) (*Result, error) {
	return nil, ErrNotImplemented
}

// extractPredicate returns the parsed proto message carried by the
// statement's predicate. The collector wiring is
// responsible for populating this field with one of the registered
// SLSA proto messages.
func extractPredicate(stmt attestation.Statement) (proto.Message, error) {
	p := stmt.GetPredicate()
	if p == nil {
		return nil, errors.New("statement has no predicate")
	}
	parsed := p.GetParsed()
	if parsed == nil {
		return nil, errors.New("predicate has no parsed payload")
	}
	msg, ok := parsed.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("predicate parsed payload is not a proto message (got %T)", parsed)
	}
	return msg, nil
}

// convertSubjects projects the attestation.Subject interface onto the
// concrete in-toto ResourceDescriptor type so CEL can iterate over it
// using the registered proto descriptor.
func convertSubjects(subs []attestation.Subject) []*intoto.ResourceDescriptor {
	out := make([]*intoto.ResourceDescriptor, len(subs))
	for i, s := range subs {
		out[i] = &intoto.ResourceDescriptor{
			Name:   s.GetName(),
			Uri:    s.GetUri(),
			Digest: s.GetDigest(),
		}
	}
	return out
}
