// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector/envelope"
	provenancev01 "github.com/in-toto/attestation/go/predicates/provenance/v01"
	provenancev02 "github.com/in-toto/attestation/go/predicates/provenance/v02"
	provenancev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	sourceprovenance "github.com/slsa-framework/source-tool/pkg/provenance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa"
	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/eval"
)

// loadFixture parses a fixture through the public collector envelope
// path — the same code the CLI runs.
func loadFixture(t *testing.T, name string) attestation.Statement {
	t.Helper()
	envs, err := envelope.Parsers.ParseFiles([]string{filepath.Join("testdata", "plain", name)})
	require.NoError(t, err, "parsing fixture %s", name)
	require.Len(t, envs, 1)
	stmt := envs[0].GetStatement()
	require.NotNil(t, stmt)
	return stmt
}

// TestFixturesParseToExpectedProtoType walks every plain fixture and
// asserts the predicate type matches the expected URI and the parsed
// payload is the matching upstream proto message — this verifies the
// pkg/slsa/predicate registry routing for all four supported types in
// one place.
func TestFixturesParseToExpectedProtoType(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		predicateID string
		wantPB      func(proto.Message) bool
	}{
		{
			name:        "v01-build.intoto.json",
			predicateID: eval.PredicateProvenanceV01,
			wantPB: func(m proto.Message) bool {
				_, ok := m.(*provenancev01.Provenance)
				return ok
			},
		},
		{
			name:        "v02-build.intoto.json",
			predicateID: eval.PredicateProvenanceV02,
			wantPB: func(m proto.Message) bool {
				_, ok := m.(*provenancev02.Provenance)
				return ok
			},
		},
		{
			name:        "v1-build.intoto.json",
			predicateID: eval.PredicateProvenanceV1,
			wantPB: func(m proto.Message) bool {
				_, ok := m.(*provenancev1.Provenance)
				return ok
			},
		},
		{
			name:        "source.intoto.json",
			predicateID: eval.PredicateSourceProvenance,
			wantPB: func(m proto.Message) bool {
				_, ok := m.(*sourceprovenance.SourceProvenancePred)
				return ok
			},
		},
		{
			name:        "tag.intoto.json",
			predicateID: eval.PredicateTagProvenance,
			wantPB: func(m proto.Message) bool {
				_, ok := m.(*sourceprovenance.TagProvenancePred)
				return ok
			},
		},
		{
			name:        "source-v1.intoto.json",
			predicateID: eval.PredicateSourceProvenanceV1,
			wantPB: func(m proto.Message) bool {
				_, ok := m.(*sourceprovenance.SourceProvenancePred)
				return ok
			},
		},
		{
			name:        "tag-v1.intoto.json",
			predicateID: eval.PredicateTagProvenanceV1,
			wantPB: func(m proto.Message) bool {
				_, ok := m.(*sourceprovenance.TagProvenancePred)
				return ok
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stmt := loadFixture(t, tc.name)
			assert.Equal(t, attestation.PredicateType(tc.predicateID), stmt.GetPredicateType())

			parsed, ok := stmt.GetPredicate().GetParsed().(proto.Message)
			require.True(t, ok, "GetParsed should return a proto.Message")
			assert.True(t, tc.wantPB(parsed), "wrong proto type for %s: got %T", tc.name, parsed)
		})
	}
}

// TestVerifyV1FixtureEndToEnd runs the v1 build fixture through the full
// public Verify flow with all five embedded core controls and confirms a
// PASS at SLSA level 3.
func TestVerifyV1FixtureEndToEnd(t *testing.T) {
	t.Parallel()

	stmt := loadFixture(t, "v1-build.intoto.json")
	v, err := slsa.New()
	require.NoError(t, err)

	res, err := v.Verify(
		context.Background(),
		stmt,
		slsa.WithParam("expected_source", "git+https://example.com/repo"),
		slsa.WithParam("trusted_builders", []string{"https://example.com/builder"}),
	)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 3, res.SLSALevel)
}

// TestVerifyV02FixtureReachesLevel3 confirms the v0.2 build fixture
// passes all five build/core controls (each control carries a
// version-specific check now) and reaches Level 3 with matching
// params.
func TestVerifyV02FixtureReachesLevel3(t *testing.T) {
	t.Parallel()

	stmt := loadFixture(t, "v02-build.intoto.json")
	v, err := slsa.New()
	require.NoError(t, err)

	res, err := v.Verify(
		context.Background(),
		stmt,
		slsa.WithParam("expected_source", "git+https://example.com/repo"),
		slsa.WithParam("trusted_builders", []string{"https://example.com/builder/v0.2"}),
	)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 3, res.SLSALevel)
}

// TestVerifyV01FixtureReachesLevel3 — same as v0.2 but for v0.1.
func TestVerifyV01FixtureReachesLevel3(t *testing.T) {
	t.Parallel()

	stmt := loadFixture(t, "v01-build.intoto.json")
	v, err := slsa.New()
	require.NoError(t, err)

	res, err := v.Verify(
		context.Background(),
		stmt,
		slsa.WithParam("expected_source", "git+https://example.com/repo"),
		slsa.WithParam("trusted_builders", []string{"https://example.com/builder/v0.1"}),
	)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 3, res.SLSALevel)
}

// TestVerifySourceFixtureReachesLevel4 confirms the source fixture
// passes every SourceCore control (L1 expectation checks + the 13
// SLSA_SOURCE_* named controls) and reaches Level 4. Also confirms
// BuildType is empty for source statements (the gating fix).
func TestVerifySourceFixtureReachesLevel4(t *testing.T) {
	t.Parallel()

	stmt := loadFixture(t, "source.intoto.json")
	v, err := slsa.New()
	require.NoError(t, err)

	res, err := v.Verify(
		context.Background(),
		stmt,
		slsa.WithParam("expected_source_repo", "https://github.com/example/repo"),
		slsa.WithParam("expected_branch", "refs/heads/main"),
	)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 4, res.SLSALevel)

	// Source statements get no BuildType controls.
	assert.Empty(t, res.BuildTypeResults, "source statements should produce no BuildType results")

	// 13 named source controls + 3 expectation checks + 5 tag controls
	// (the tag entries report as skipped on branch provenance).
	assert.Len(t, res.CoreResults, 21)
}

// TestVerifySourceFixtureWithoutParams confirms the expectation checks
// (expected_source_repo / expected_branch) are skipped — not errored —
// when the caller states no expectations, and the level still computes.
func TestVerifySourceFixtureWithoutParams(t *testing.T) {
	t.Parallel()

	stmt := loadFixture(t, "source.intoto.json")
	v, err := slsa.New()
	require.NoError(t, err)

	res, err := v.Verify(context.Background(), stmt)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 4, res.SLSALevel)

	for _, cr := range res.CoreResults {
		if cr.ID == "source-repo-match" || cr.ID == "source-branch-match" {
			assert.Equal(t, slsa.StatusSkipped, cr.Status,
				"expectation check %s should be skipped without params", cr.ID)
		}
	}
}

// TestVerifyFinalPredicateTypes confirms the final (non-draft) source
// and tag predicate types are verified exactly like the draft versions.
func TestVerifyFinalPredicateTypes(t *testing.T) {
	t.Parallel()

	v, err := slsa.New()
	require.NoError(t, err)

	res, err := v.Verify(context.Background(), loadFixture(t, "source-v1.intoto.json"))
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 4, res.SLSALevel)

	res, err = v.Verify(
		context.Background(),
		loadFixture(t, "tag-v1.intoto.json"),
		slsa.WithMinLevel(1),
		slsa.WithParam("expected_tag", "v1.2.3"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 3, res.SLSALevel)
}

// TestVerifyTagFixture confirms tag provenance verification: the tag
// inherits the level attested by the VSA summaries of the tagged
// commit, gated by the tag hygiene control at L2, and the expectation
// checks match the tag predicate's fields.
func TestVerifyTagFixture(t *testing.T) {
	t.Parallel()

	stmt := loadFixture(t, "tag.intoto.json")
	v, err := slsa.New()
	require.NoError(t, err)

	// The fixture's VSA summary attests L3; hygiene is active.
	res, err := v.Verify(
		context.Background(),
		stmt,
		slsa.WithMinLevel(1),
		slsa.WithParam("expected_source_repo", "https://github.com/example/repo"),
		slsa.WithParam("expected_branch", "refs/heads/main"),
		slsa.WithParam("expected_tag", "v1.2.3"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 3, res.SLSALevel)

	// All branch-provenance controls must have been skipped.
	for _, cr := range res.CoreResults {
		if cr.ID == "source-control-org-scs" || cr.ID == "source-control-scs-continuity" {
			assert.Equal(t, slsa.StatusSkipped, cr.Status, "branch control %s should skip on tag provenance", cr.ID)
		}
	}

	// A wrong expected tag fails the run.
	res, err = v.Verify(
		context.Background(),
		stmt,
		slsa.WithMinLevel(1),
		slsa.WithParam("expected_tag", "v9.9.9"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusFail, res.Status)

	// A branch not covered by the VSA summaries fails the run.
	res, err = v.Verify(
		context.Background(),
		stmt,
		slsa.WithMinLevel(1),
		slsa.WithParam("expected_branch", "refs/heads/other"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusFail, res.Status)

	// An enforcement date predating the hygiene control fails the
	// L2 gate: the tag caps at level 1 (sourcetool's no-hygiene
	// degrade), passing only when no higher level is required.
	res, err = v.Verify(
		context.Background(),
		stmt,
		slsa.WithMinLevel(1),
		slsa.WithParam("enforced_since", "2025-01-01T00:00:00Z"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 1, res.SLSALevel)

	res, err = v.Verify(
		context.Background(),
		stmt,
		slsa.WithMinLevel(3),
		slsa.WithParam("enforced_since", "2025-01-01T00:00:00Z"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusFail, res.Status)
}

// TestVerifySourceFixtureEnforcedSince confirms the enforced_since param
// fails controls activated after the given date: the fixture's
// two-party review control (since 2025-12-01) drops off, capping the
// level at 3, and the run fails unless MinLevel makes L4 informative.
func TestVerifySourceFixtureEnforcedSince(t *testing.T) {
	t.Parallel()

	stmt := loadFixture(t, "source.intoto.json")
	v, err := slsa.New()
	require.NoError(t, err)

	// Strict (MinLevel unset): the failing L4 control fails the run.
	res, err := v.Verify(
		context.Background(),
		stmt,
		slsa.WithParam("enforced_since", "2025-08-01T00:00:00Z"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusFail, res.Status)
	assert.Equal(t, 3, res.SLSALevel)

	// With MinLevel 3 the L4 control is informative: PASS at level 3.
	res, err = v.Verify(
		context.Background(),
		stmt,
		slsa.WithParam("enforced_since", "2025-08-01T00:00:00Z"),
		slsa.WithMinLevel(3),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 3, res.SLSALevel)

	// An enforcement date before every control's continuity window
	// cuts deeper: 2025-07-01 predates the L2 continuity control.
	res, err = v.Verify(
		context.Background(),
		stmt,
		slsa.WithParam("enforced_since", "2025-07-01T00:00:00Z"),
		slsa.WithMinLevel(1),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 1, res.SLSALevel)
}

// TestVerifySourceFixtureMissingSinceFails confirms a control listed
// without a since timestamp does not count: the window during which it
// was enforced cannot be established, with or without --since. An
// explicit epoch (the fixture's provenance control) is still a value and
// still counts.
func TestVerifySourceFixtureMissingSinceFails(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("testdata", "plain", "source.intoto.json"))
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	predicate, ok := doc["predicate"].(map[string]any)
	require.True(t, ok)
	controls, ok := predicate["controls"].([]any)
	require.True(t, ok)
	stripped := 0
	for _, c := range controls {
		control, ok := c.(map[string]any)
		require.True(t, ok)
		if control["name"] == "SLSA_SOURCE_ORG_ACCESS_CONTROL" {
			delete(control, "since")
			stripped++
		}
	}
	require.Equal(t, 1, stripped)
	mutated, err := json.Marshal(doc)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "source-no-since.intoto.json")
	require.NoError(t, os.WriteFile(path, mutated, 0o600))

	envs, err := envelope.Parsers.ParseFiles([]string{path})
	require.NoError(t, err)
	require.Len(t, envs, 1)
	stmt := envs[0].GetStatement()
	require.NotNil(t, stmt)

	v, err := slsa.New()
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		opts []slsa.VerificationOption
	}{
		{"without --since", nil},
		{"with --since", []slsa.VerificationOption{slsa.WithParam("enforced_since", "2025-01-01T00:00:00Z")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := v.Verify(context.Background(), stmt, tc.opts...)
			require.NoError(t, err)
			assert.Equal(t, slsa.StatusFail, res.Status)

			var accessControl *slsa.ControlResult
			for _, cr := range res.CoreResults {
				if cr.ID == "source-control-org-access-control" {
					accessControl = cr
				}
			}
			require.NotNil(t, accessControl)
			assert.Equal(t, slsa.StatusFail, accessControl.Status, "a control without since must not count")
			// The L2 control failing caps the level at 1.
			assert.Equal(t, 1, res.SLSALevel)
		})
	}
}
