// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package predicate_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/carabiner-dev/attestation"
	provenancev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/eval"
	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/predicate"
)

const sampleProvenanceV1JSON = `{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {"name": "out/binary", "digest": {"sha256": "deadbeef"}}
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://example.com/buildType/v1",
      "externalParameters": {
        "source": "git+https://example.com/repo"
      }
    },
    "runDetails": {
      "builder": {"id": "https://example.com/builder"}
    }
  }
}`

func TestParseStatementSLSAv1(t *testing.T) {
	t.Parallel()

	stmt, err := predicate.ParseStatement([]byte(sampleProvenanceV1JSON))
	require.NoError(t, err)
	require.NotNil(t, stmt)

	assert.Equal(t, attestation.PredicateType(eval.PredicateProvenanceV1), stmt.GetPredicateType())
	require.Len(t, stmt.GetSubjects(), 1)
	assert.Equal(t, "out/binary", stmt.GetSubjects()[0].GetName())
	assert.Equal(t, "deadbeef", stmt.GetSubjects()[0].GetDigest()["sha256"])

	pred, ok := stmt.GetPredicate().GetParsed().(*provenancev1.Provenance)
	require.True(t, ok, "predicate parsed payload should be *provenancev1.Provenance")
	assert.Equal(t, "https://example.com/builder", pred.GetRunDetails().GetBuilder().GetId())
}

func TestParseStatementUnsupportedPredicate(t *testing.T) {
	t.Parallel()

	src := `{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": [{"digest": {"sha256": "x"}}],
		"predicateType": "https://example.com/some-other-attestation/v1",
		"predicate": {}
	}`
	_, err := predicate.ParseStatement([]byte(src))
	assert.ErrorIs(t, err, predicate.ErrUnsupportedPredicate)
}

func TestParseStatementEmptyPredicateType(t *testing.T) {
	t.Parallel()

	src := `{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": [{"digest": {"sha256": "x"}}],
		"predicate": {}
	}`
	_, err := predicate.ParseStatement([]byte(src))
	assert.Error(t, err)
}

func TestParseStatementInvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := predicate.ParseStatement([]byte(`not json`))
	assert.Error(t, err)
}

func TestParsePredicateRejectsUnknownType(t *testing.T) {
	t.Parallel()

	_, err := predicate.ParsePredicate(
		attestation.PredicateType("https://example.com/unknown"),
		[]byte(`{}`),
	)
	assert.ErrorIs(t, err, predicate.ErrUnsupportedPredicate)
}

func TestLoadStatement(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "provenance.intoto.json")
	require.NoError(t, os.WriteFile(path, []byte(sampleProvenanceV1JSON), 0o600))

	stmt, err := predicate.LoadStatement(path)
	require.NoError(t, err)
	assert.Equal(t, attestation.PredicateType(eval.PredicateProvenanceV1), stmt.GetPredicateType())
}

func TestLoadStatementMissingFile(t *testing.T) {
	t.Parallel()

	_, err := predicate.LoadStatement(filepath.Join(t.TempDir(), "nope.json"))
	assert.Error(t, err)
}

func TestPredicateImplementsAttestationPredicate(t *testing.T) {
	t.Parallel()

	var _ attestation.Predicate = (*predicate.Predicate)(nil)
	var _ attestation.Statement = (*predicate.Statement)(nil)
}
