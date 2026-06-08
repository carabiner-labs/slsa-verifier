// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"context"
	"errors"
	"testing"

	cdattestation "github.com/carabiner-dev/attestation"
	vsav1 "github.com/in-toto/attestation/go/predicates/vsa/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/vsa"
)

// fakePredicate is a minimal attestation.Predicate for unit tests —
// only the methods VerifyVSA reaches need real bodies; the rest
// return zero values.
type fakePredicate struct {
	parsed any
	pType  cdattestation.PredicateType
}

func (p *fakePredicate) GetType() cdattestation.PredicateType { return p.pType }
func (p *fakePredicate) SetType(t cdattestation.PredicateType) error {
	p.pType = t
	return nil
}
func (p *fakePredicate) GetParsed() any                               { return p.parsed }
func (p *fakePredicate) GetData() []byte                              { return nil }
func (p *fakePredicate) GetVerification() cdattestation.Verification  { return nil }
func (p *fakePredicate) GetOrigin() cdattestation.Subject             { return nil }
func (p *fakePredicate) SetOrigin(_ cdattestation.Subject)            {}
func (p *fakePredicate) SetVerification(_ cdattestation.Verification) {}

// fakeStmt is a minimal attestation.Statement for unit tests.
type fakeStmt struct {
	pType cdattestation.PredicateType
	pred  cdattestation.Predicate
}

func (s *fakeStmt) GetSubjects() []cdattestation.Subject          { return nil }
func (s *fakeStmt) GetPredicate() cdattestation.Predicate         { return s.pred }
func (s *fakeStmt) GetPredicateType() cdattestation.PredicateType { return s.pType }
func (s *fakeStmt) GetType() string                               { return "" }
func (s *fakeStmt) GetVerification() cdattestation.Verification   { return nil }

// fakeEnvelope is a minimal attestation.Envelope wrapping a fakeStmt.
// The only methods VerifyVSA touches are GetStatement; the rest
// satisfy the interface with zero values.
type fakeEnvelope struct {
	stmt cdattestation.Statement
	sigs []cdattestation.Signature
}

func (e *fakeEnvelope) GetStatement() cdattestation.Statement       { return e.stmt }
func (e *fakeEnvelope) GetPredicate() cdattestation.Predicate       { return nil }
func (e *fakeEnvelope) GetSignatures() []cdattestation.Signature    { return e.sigs }
func (e *fakeEnvelope) GetCertificate() cdattestation.Certificate   { return nil }
func (e *fakeEnvelope) GetVerification() cdattestation.Verification { return nil }
func (e *fakeEnvelope) Verify(_ ...any) error                       { return nil }

// vsaEnv builds a fake envelope carrying a SLSA VSA v1 proto with
// the fields each test cares about. Optional fields default to
// empty / nil; populate via the modifier.
func vsaEnv(mod func(*vsav1.VerificationSummary)) *fakeEnvelope {
	pred := &vsav1.VerificationSummary{
		Verifier:           &vsav1.VerificationSummary_Verifier{Id: "https://verify.example.com"},
		ResourceUri:        "pkg:oci/foo@sha256:abc",
		VerificationResult: vsa.ResultPassed,
		VerifiedLevels:     []string{"SLSA_BUILD_LEVEL_3"},
		DependencyLevels:   map[string]uint64{"SLSA_BUILD_LEVEL_2": 5},
	}
	if mod != nil {
		mod(pred)
	}
	return &fakeEnvelope{
		stmt: &fakeStmt{
			pType: cdattestation.PredicateType(vsa.PredicateTypeV1),
			pred:  &fakePredicate{pType: cdattestation.PredicateType(vsa.PredicateTypeV1), parsed: pred},
		},
	}
}

func TestVerifyVSAAllChecksPass(t *testing.T) {
	t.Parallel()

	v := New()
	result, err := v.VerifyVSA(context.Background(), vsaEnv(nil), VSAOptions{
		Verifier:     "https://verify.example.com",
		Levels:       []string{"SLSA_BUILD_LEVEL_3"},
		Resource:     "pkg:oci/foo@sha256:abc",
		Dependencies: []string{"SLSA_BUILD_LEVEL_2"},
	})
	require.NoError(t, err)
	assert.True(t, result.Pass(), "expected all checks to pass")
	for _, c := range result.Checks {
		assert.True(t, c.Pass, "check %q should pass", c.Name)
	}
}

func TestVerifyVSAResultMustBePassed(t *testing.T) {
	t.Parallel()

	env := vsaEnv(func(p *vsav1.VerificationSummary) {
		p.VerificationResult = vsa.ResultFailed
	})
	result, err := New().VerifyVSA(context.Background(), env, VSAOptions{
		Verifier: "https://verify.example.com",
	})
	require.NoError(t, err)
	assert.False(t, result.Pass())
	// The result-PASSED check must be the failing one.
	var failed []string
	for _, c := range result.Checks {
		if !c.Pass {
			failed = append(failed, c.Name)
		}
	}
	require.Len(t, failed, 1)
	assert.Contains(t, failed[0], "Result is PASSED")
}

func TestVerifyVSAVerifierMismatchFails(t *testing.T) {
	t.Parallel()

	result, err := New().VerifyVSA(context.Background(), vsaEnv(nil), VSAOptions{
		Verifier: "https://other.example.com",
	})
	require.NoError(t, err)
	assert.False(t, result.Pass())
}

func TestVerifyVSALevelOrMatched(t *testing.T) {
	t.Parallel()

	// fixture has verifiedLevels = ["SLSA_BUILD_LEVEL_3"]
	// At-least one of the listed wants must be satisfied. Both pass
	// here (the second is the actual level, the first is below it
	// and is satisfied by at-or-above semantics).
	result, err := New().VerifyVSA(context.Background(), vsaEnv(nil), VSAOptions{
		Verifier: "https://verify.example.com",
		Levels:   []string{"SLSA_BUILD_LEVEL_4", "SLSA_BUILD_LEVEL_3"},
	})
	require.NoError(t, err)
	assert.True(t, result.Pass())
}

func TestVerifyVSALevelAtOrAboveSatisfies(t *testing.T) {
	t.Parallel()

	// VSA reports LEVEL_4, want LEVEL_3 → satisfied.
	env := vsaEnv(func(p *vsav1.VerificationSummary) {
		p.VerifiedLevels = []string{"SLSA_BUILD_LEVEL_4"}
	})
	result, err := New().VerifyVSA(context.Background(), env, VSAOptions{
		Verifier: "https://verify.example.com",
		Levels:   []string{"SLSA_BUILD_LEVEL_3"},
	})
	require.NoError(t, err)
	assert.True(t, result.Pass(),
		"VSA at SLSA_BUILD_LEVEL_4 must satisfy --level SLSA_BUILD_LEVEL_3")
}

func TestVerifyVSALevelBelowWantFails(t *testing.T) {
	t.Parallel()

	// fixture has SLSA_BUILD_LEVEL_3, want LEVEL_4 → fails (3 < 4).
	result, err := New().VerifyVSA(context.Background(), vsaEnv(nil), VSAOptions{
		Verifier: "https://verify.example.com",
		Levels:   []string{"SLSA_BUILD_LEVEL_4"},
	})
	require.NoError(t, err)
	assert.False(t, result.Pass())
}

func TestVerifyVSALevelDifferentTrackFails(t *testing.T) {
	t.Parallel()

	// VSA reports SLSA_BUILD_LEVEL_4; want a SOURCE level. Different
	// track → no satisfaction even at a higher number.
	env := vsaEnv(func(p *vsav1.VerificationSummary) {
		p.VerifiedLevels = []string{"SLSA_BUILD_LEVEL_4"}
	})
	result, err := New().VerifyVSA(context.Background(), env, VSAOptions{
		Verifier: "https://verify.example.com",
		Levels:   []string{"SLSA_SOURCE_LEVEL_3"},
	})
	require.NoError(t, err)
	assert.False(t, result.Pass(),
		"different track must not satisfy regardless of level number")
}

func TestVerifyVSADependenciesAndMatched(t *testing.T) {
	t.Parallel()

	// Every requested key must be present (AND semantics).
	env := vsaEnv(func(p *vsav1.VerificationSummary) {
		p.DependencyLevels = map[string]uint64{"SLSA_BUILD_LEVEL_2": 1}
	})
	result, err := New().VerifyVSA(context.Background(), env, VSAOptions{
		Verifier:     "https://verify.example.com",
		Dependencies: []string{"SLSA_BUILD_LEVEL_2", "SLSA_BUILD_LEVEL_3"},
	})
	require.NoError(t, err)
	assert.False(t, result.Pass(),
		"missing SLSA_BUILD_LEVEL_3 in dependencyLevels must fail when AND-matched")
}

func TestVerifyVSAVerifierRequiredOnOptions(t *testing.T) {
	t.Parallel()

	_, err := New().VerifyVSA(context.Background(), vsaEnv(nil), VSAOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Verifier is required")
}

func TestVerifyVSANilEnvelope(t *testing.T) {
	t.Parallel()

	_, err := New().VerifyVSA(context.Background(), nil, VSAOptions{
		Verifier: "https://verify.example.com",
	})
	require.Error(t, err)
}

func TestVerifyVSANonVSAPredicateReturnsErrNotVSA(t *testing.T) {
	t.Parallel()

	env := &fakeEnvelope{
		stmt: &fakeStmt{
			pType: "https://slsa.dev/provenance/v1",
			pred:  &fakePredicate{pType: "https://slsa.dev/provenance/v1", parsed: nil},
		},
	}
	_, err := New().VerifyVSA(context.Background(), env, VSAOptions{
		Verifier: "https://verify.example.com",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, vsa.ErrNotVSA), "expected ErrNotVSA, got %v", err)
}
