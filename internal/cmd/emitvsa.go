// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"io"
	"time"

	cdattestation "github.com/carabiner-dev/attestation"
	intoto "github.com/in-toto/attestation/go/v1"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa"
	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/controls"
	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/vsa"
)

// verifierID is the verifier.id recorded in the VSAs this tool emits. It
// identifies slsa-verifier as the entity that produced the summary.
const verifierID = "https://github.com/carabiner-labs/slsa-verifier"

// emitVSA writes an unsigned VSA v1 statement describing result to w. The
// statement records the computed SLSA level (as verifiedLevels for the
// given track), the overall PASSED/FAILED outcome, and the subjects of
// the verified attestation. It is the shared output path for the build
// and source verifiers when their --vsa flag is set.
func emitVSA(w io.Writer, stmt cdattestation.Statement, result *slsa.Result, track controls.Track) error {
	subjects := vsaSubjects(stmt)
	// Prefer the identity carried on the result (set through
	// WithVerifierID); fall back to this tool's own ID when a caller ran
	// the verification without supplying one.
	id := result.VerifierID
	if id == "" {
		id = verifierID
	}
	in := vsa.SummaryInput{
		VerifierID:         id,
		TimeVerified:       time.Now(),
		Subjects:           subjects,
		VerificationResult: vsaResult(result),
		VerifiedLevels:     verifiedLevels(track, result.SLSALevel),
	}
	// Use the first subject's URI as the resource the VSA covers, when one
	// is available.
	if len(subjects) > 0 {
		in.ResourceURI = subjects[0].GetUri()
	}

	statement, err := in.Statement()
	if err != nil {
		return err
	}
	data, err := vsa.Marshal(statement)
	if err != nil {
		return err
	}
	writef(w, "%s\n", data)
	return nil
}

// vsaResult maps a verification Result onto the VSA verificationResult
// vocabulary.
func vsaResult(result *slsa.Result) string {
	if result.Pass() {
		return vsa.ResultPassed
	}
	return vsa.ResultFailed
}

// verifiedLevels renders the computed SLSA level as the canonical
// verifiedLevels entry for the track, e.g. "SLSA_BUILD_LEVEL_3". A
// non-positive level (nothing established) yields an empty list.
func verifiedLevels(track controls.Track, level int) []string {
	if level <= 0 {
		return nil
	}
	prefix := "SLSA_BUILD_LEVEL_"
	if track == controls.TrackSource {
		prefix = "SLSA_SOURCE_LEVEL_"
	}
	return []string{fmt.Sprintf("%s%d", prefix, level)}
}

// vsaSubjects projects the verified statement's subjects onto the
// concrete in-toto ResourceDescriptor type the VSA statement carries.
func vsaSubjects(stmt cdattestation.Statement) []*intoto.ResourceDescriptor {
	if stmt == nil {
		return nil
	}
	subs := stmt.GetSubjects()
	out := make([]*intoto.ResourceDescriptor, 0, len(subs))
	for _, s := range subs {
		if s == nil {
			continue
		}
		out = append(out, &intoto.ResourceDescriptor{
			Name:   s.GetName(),
			Uri:    s.GetUri(),
			Digest: s.GetDigest(),
		})
	}
	return out
}
