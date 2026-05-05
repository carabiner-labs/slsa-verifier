// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package eval_test

import (
	"testing"

	provenancev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/eval"
)

func TestFillNilMessagesAllocatesSubMessages(t *testing.T) {
	t.Parallel()

	pred := &provenancev1.Provenance{}
	require.Nil(t, pred.GetBuildDefinition(), "precondition: BuildDefinition starts nil")
	require.Nil(t, pred.GetRunDetails(), "precondition: RunDetails starts nil")

	eval.FillNilMessages(pred)

	require.NotNil(t, pred.GetBuildDefinition(), "BuildDefinition allocated")
	require.NotNil(t, pred.GetRunDetails(), "RunDetails allocated")
	require.NotNil(t, pred.GetRunDetails().GetBuilder(), "Builder allocated")
	require.NotNil(t, pred.GetRunDetails().GetMetadata(), "Metadata allocated")
	assert.Empty(t, pred.GetRunDetails().GetBuilder().GetId())
}

func TestFillNilMessagesEnablesChainedCELAccessOnEmptyPredicate(t *testing.T) {
	t.Parallel()

	e, err := eval.NewEvaluator()
	require.NoError(t, err)

	pred := &provenancev1.Provenance{}
	eval.FillNilMessages(pred)

	pass, err := e.Evaluate(
		eval.PredicateProvenanceV1,
		`predicate.runDetails.builder.id == ""`,
		pred, nil, nil,
	)
	require.NoError(t, err, "chained access through nil-but-now-zero fields should not error")
	assert.True(t, pass)

	pass, err = e.Evaluate(
		eval.PredicateProvenanceV1,
		`predicate.runDetails.builder.id != ""`,
		pred, nil, nil,
	)
	require.NoError(t, err)
	assert.False(t, pass, "empty builder id should compare as != \"\" → false")
}

func TestFillNilMessagesPreservesPopulatedFields(t *testing.T) {
	t.Parallel()

	pred := &provenancev1.Provenance{
		RunDetails: &provenancev1.RunDetails{
			Builder: &provenancev1.Builder{Id: "https://example.com/builder"},
		},
	}
	eval.FillNilMessages(pred)
	assert.Equal(t, "https://example.com/builder", pred.GetRunDetails().GetBuilder().GetId())
}

func TestFillNilMessagesWalksRepeatedMessages(t *testing.T) {
	t.Parallel()

	pred := &provenancev1.Provenance{
		BuildDefinition: &provenancev1.BuildDefinition{
			ResolvedDependencies: []*intoto.ResourceDescriptor{
				{}, // empty entry — should still produce a valid descriptor after fill
			},
		},
	}
	eval.FillNilMessages(pred)
	require.Len(t, pred.GetBuildDefinition().GetResolvedDependencies(), 1)
	// The entry remains a valid (empty) descriptor; nothing crashed.
}

func TestFillNilMessagesNilSafe(t *testing.T) {
	t.Parallel()
	eval.FillNilMessages(nil) // must not panic
}
