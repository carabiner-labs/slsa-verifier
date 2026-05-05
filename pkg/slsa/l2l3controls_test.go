// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"context"
	"testing"

	"github.com/carabiner-dev/attestation"
	provenancev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/controls"
	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/eval"
)

// fullV1Stmt builds a v1 provenance fixture populated with all the
// fields the new L2/L3 controls inspect.
func fullV1Stmt(t *testing.T) *fakeStmt {
	t.Helper()
	ext, err := structpb.NewStruct(map[string]any{"source": "git+https://example.com/repo"})
	require.NoError(t, err)
	return &fakeStmt{
		pType: attestation.PredicateType(eval.PredicateProvenanceV1),
		pred: &fakePredicate{
			pType: attestation.PredicateType(eval.PredicateProvenanceV1),
			parsed: &provenancev1.Provenance{
				BuildDefinition: &provenancev1.BuildDefinition{
					BuildType:          "https://example.com/buildType@v1",
					ExternalParameters: ext,
					ResolvedDependencies: []*intoto.ResourceDescriptor{
						{Uri: "git+https://example.com/dep", Digest: map[string]string{"sha256": "abc"}},
					},
				},
				RunDetails: &provenancev1.RunDetails{
					Builder: &provenancev1.Builder{Id: "https://example.com/builder"},
					Metadata: &provenancev1.BuildMetadata{
						InvocationId: "build-1234",
					},
				},
			},
		},
	}
}

// findEmbedded returns the embedded core control with id, or fails the
// test if it isn't present.
func findEmbedded(t *testing.T, id string) *controls.Control {
	t.Helper()
	cat, err := controls.LoadEmbedded()
	require.NoError(t, err)
	for _, c := range cat.Get(controls.BuildCore) {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("embedded control %q not found in build/core", id)
	return nil
}

func TestEmbeddedL2L3ControlsLoad(t *testing.T) {
	t.Parallel()

	cases := []struct {
		id    string
		level int
	}{
		{"source-repo-match", 1},
		{"builder-id-trusted", 2},
		{"provenance-l2-complete", 2},
		{"provenance-has-invocation-id", 3},
		{"provenance-has-resolved-dependencies", 3},
	}
	for _, tc := range cases {
		c := findEmbedded(t, tc.id)
		assert.Equal(t, tc.level, c.SLSALevel, "%s slsaLevel", tc.id)
		require.NotEmpty(t, c.Checks)
		assert.Equal(t, eval.PredicateProvenanceV1, c.Checks[0].PredicateType)
	}
}

func TestBuilderTrustedPasses(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := fullV1Stmt(t)
	ctrls := []*controls.Control{findEmbedded(t, "builder-id-trusted")}

	opts := &VerificationOptions{
		Params: map[string]any{
			"trusted_builders": []string{"https://example.com/builder", "https://other.example.com/builder"},
		},
	}
	results, err := impl.RunControls(context.Background(), opts, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusPass, results[0].Status)
	assert.Equal(t, 2, results[0].SLSALevel)
}

func TestBuilderTrustedFailsForUntrustedBuilder(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := fullV1Stmt(t)
	ctrls := []*controls.Control{findEmbedded(t, "builder-id-trusted")}

	opts := &VerificationOptions{
		Params: map[string]any{
			"trusted_builders": []string{"https://other.example.com/builder"},
		},
	}
	results, err := impl.RunControls(context.Background(), opts, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusFail, results[0].Status)
}

func TestBuilderTrustedMissingParamErrors(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := fullV1Stmt(t)
	ctrls := []*controls.Control{findEmbedded(t, "builder-id-trusted")}

	results, err := impl.RunControls(context.Background(), &VerificationOptions{Params: map[string]any{}}, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusError, results[0].Status)
	assert.Contains(t, results[0].Message, "trusted_builders")
}

func TestProvenanceL2CompleteHappyPath(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := fullV1Stmt(t)
	ctrls := []*controls.Control{findEmbedded(t, "provenance-l2-complete")}

	results, err := impl.RunControls(context.Background(), &VerificationOptions{}, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusPass, results[0].Status)
}

func TestProvenanceL2CompleteFailsWhenBuilderMissing(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := fullV1Stmt(t)
	pred, ok := stmt.pred.GetParsed().(*provenancev1.Provenance)
	require.True(t, ok)
	pred.RunDetails.Builder.Id = ""

	ctrls := []*controls.Control{findEmbedded(t, "provenance-l2-complete")}
	results, err := impl.RunControls(context.Background(), &VerificationOptions{}, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusFail, results[0].Status)
}

func TestInvocationIdControl(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := fullV1Stmt(t)
	ctrls := []*controls.Control{findEmbedded(t, "provenance-has-invocation-id")}

	// Happy path.
	results, err := impl.RunControls(context.Background(), &VerificationOptions{}, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusPass, results[0].Status)
	assert.Equal(t, 3, results[0].SLSALevel)

	// Stripped invocation ID — should fail.
	pred, ok := stmt.pred.GetParsed().(*provenancev1.Provenance)
	require.True(t, ok)
	pred.RunDetails.Metadata.InvocationId = ""
	results, err = impl.RunControls(context.Background(), &VerificationOptions{}, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusFail, results[0].Status)
}

func TestResolvedDependenciesControl(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := fullV1Stmt(t)
	ctrls := []*controls.Control{findEmbedded(t, "provenance-has-resolved-dependencies")}

	// Happy path.
	results, err := impl.RunControls(context.Background(), &VerificationOptions{}, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusPass, results[0].Status)
	assert.Equal(t, 3, results[0].SLSALevel)

	// Empty resolved dependencies — should fail.
	pred, ok := stmt.pred.GetParsed().(*provenancev1.Provenance)
	require.True(t, ok)
	pred.BuildDefinition.ResolvedDependencies = nil
	results, err = impl.RunControls(context.Background(), &VerificationOptions{}, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusFail, results[0].Status)
}

// TestSLSALevelClimbsWhenAllLevelsPass exercises ComputeResult with the
// new L2/L3 controls so we can confirm the level computation reaches 3
// when every level's controls pass.
func TestSLSALevelClimbsWhenAllLevelsPass(t *testing.T) {
	t.Parallel()

	impl := &defaultImplementation{}
	r, err := impl.ComputeResult(
		nil,
		[]*ControlResult{
			{ID: "source-repo-match", SLSALevel: 1, Status: StatusPass},
			{ID: "builder-id-trusted", SLSALevel: 2, Status: StatusPass},
			{ID: "provenance-l2-complete", SLSALevel: 2, Status: StatusPass},
			{ID: "provenance-has-invocation-id", SLSALevel: 3, Status: StatusPass},
			{ID: "provenance-has-resolved-dependencies", SLSALevel: 3, Status: StatusPass},
		},
		nil, nil,
	)
	require.NoError(t, err)
	assert.Equal(t, StatusPass, r.Status)
	assert.Equal(t, 3, r.SLSALevel)
}
