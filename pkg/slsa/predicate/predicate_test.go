// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package predicate_test

import (
	"testing"

	"github.com/carabiner-dev/attestation"
	collectorpred "github.com/carabiner-dev/collector/predicate"
	provenancev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/eval"
	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/predicate"
)

func TestParserParsesV1(t *testing.T) {
	t.Parallel()

	p, ok := predicate.NewParser(attestation.PredicateType(eval.PredicateProvenanceV1))
	require.True(t, ok)

	pred, err := p.Parse([]byte(`{
		"buildDefinition": {
			"buildType": "https://example.com/buildType/v1",
			"externalParameters": {"source": "git+https://example.com/repo"}
		},
		"runDetails": {"builder": {"id": "https://example.com/builder"}}
	}`))
	require.NoError(t, err)

	parsed, ok := pred.GetParsed().(*provenancev1.Provenance)
	require.True(t, ok, "expected upstream *provenancev1.Provenance, got %T", pred.GetParsed())
	assert.Equal(t, "https://example.com/builder", parsed.GetRunDetails().GetBuilder().GetId())
}

func TestParserUnknownTypeReturnsFalse(t *testing.T) {
	t.Parallel()

	_, ok := predicate.NewParser("https://example.com/unknown")
	assert.False(t, ok)
}

func TestParserSupportsType(t *testing.T) {
	t.Parallel()

	p, _ := predicate.NewParser(attestation.PredicateType(eval.PredicateProvenanceV1))
	assert.True(t, p.SupportsType(attestation.PredicateType(eval.PredicateProvenanceV1)))
	assert.False(t, p.SupportsType("https://example.com/other"))
}

func TestParserMalformedJSONReturnsNotCorrectFormat(t *testing.T) {
	t.Parallel()

	p, _ := predicate.NewParser(attestation.PredicateType(eval.PredicateProvenanceV1))
	_, err := p.Parse([]byte(`{"unknownField": true}`))
	assert.ErrorIs(t, err, attestation.ErrNotCorrectFormat)
}

// TestInitReplacesCollectorRegistry verifies that importing this package
// installs the SLSA-only parser set on the collector's global registry.
func TestInitReplacesCollectorRegistry(t *testing.T) {
	t.Parallel()

	// All four registered predicate types should now resolve to a
	// SLSA Parser through the collector's global registry.
	for _, pt := range eval.KnownPredicateTypes() {
		got, ok := collectorpred.Parsers[attestation.PredicateType(pt)]
		require.True(t, ok, "collector global missing %s", pt)
		_, isSLSA := got.(*predicate.Parser)
		assert.True(t, isSLSA, "collector parser for %s is %T, want *predicate.Parser", pt, got)
	}

	// And no parsers for non-SLSA types should remain.
	assert.Len(t, collectorpred.Parsers, len(eval.KnownPredicateTypes()))
}
