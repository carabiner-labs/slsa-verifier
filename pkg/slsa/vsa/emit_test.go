// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package vsa

import (
	"testing"
	"time"

	vsav1 "github.com/in-toto/attestation/go/predicates/vsa/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// TestSummaryInputStatement builds a VSA statement, marshals it, and
// re-parses it to confirm the wire form carries the expected fields and
// is recognised as a VSA v1 predicate.
func TestSummaryInputStatement(t *testing.T) {
	t.Parallel()

	in := SummaryInput{
		VerifierID:         "https://example.com/verifier",
		TimeVerified:       time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC),
		ResourceURI:        "pkg:oci/foo@sha256:abc",
		VerificationResult: ResultPassed,
		VerifiedLevels:     []string{"SLSA_BUILD_LEVEL_3"},
		Subjects: []*intoto.ResourceDescriptor{
			{Name: "foo", Digest: map[string]string{"sha256": "abc"}},
		},
	}

	stmt, err := in.Statement()
	if err != nil {
		t.Fatalf("Statement: %v", err)
	}
	if stmt.GetType() != intoto.StatementTypeUri {
		t.Errorf("type = %q, want %q", stmt.GetType(), intoto.StatementTypeUri)
	}
	if stmt.GetPredicateType() != PredicateTypeV1 {
		t.Errorf("predicateType = %q, want %q", stmt.GetPredicateType(), PredicateTypeV1)
	}
	if got := len(stmt.GetSubject()); got != 1 {
		t.Fatalf("subjects = %d, want 1", got)
	}

	data, err := Marshal(stmt)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Round-trip the marshaled statement back through protojson and pull
	// the predicate out as a VSA v1 proto to confirm field fidelity.
	parsed := &intoto.Statement{}
	if err := protojson.Unmarshal(data, parsed); err != nil {
		t.Fatalf("unmarshal statement: %v", err)
	}
	predJSON, err := protojson.Marshal(parsed.GetPredicate())
	if err != nil {
		t.Fatalf("marshal predicate struct: %v", err)
	}
	pred := &vsav1.VerificationSummary{}
	if err := protojson.Unmarshal(predJSON, pred); err != nil {
		t.Fatalf("unmarshal predicate: %v", err)
	}

	if pred.GetVerifier().GetId() != in.VerifierID {
		t.Errorf("verifier.id = %q, want %q", pred.GetVerifier().GetId(), in.VerifierID)
	}
	if pred.GetVerificationResult() != ResultPassed {
		t.Errorf("verificationResult = %q, want %q", pred.GetVerificationResult(), ResultPassed)
	}
	if pred.GetResourceUri() != in.ResourceURI {
		t.Errorf("resourceUri = %q, want %q", pred.GetResourceUri(), in.ResourceURI)
	}
	if got := pred.GetVerifiedLevels(); len(got) != 1 || got[0] != "SLSA_BUILD_LEVEL_3" {
		t.Errorf("verifiedLevels = %v, want [SLSA_BUILD_LEVEL_3]", got)
	}
	if !pred.GetTimeVerified().AsTime().Equal(in.TimeVerified) {
		t.Errorf("timeVerified = %v, want %v", pred.GetTimeVerified().AsTime(), in.TimeVerified)
	}

	// And confirm the normalized read-side adapter accepts what we emit.
	got, err := FromParsed(PredicateTypeV1, pred)
	if err != nil {
		t.Fatalf("FromParsed: %v", err)
	}
	if !got.Passed() {
		t.Errorf("normalized VSA not passing: %+v", got)
	}
}
