// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"context"
	"errors"
	"fmt"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/vsa"
)

// VSAOptions configures the hardcoded checks VerifyVSA runs against
// an attestation's normalized VSA representation.
//
// Field semantics:
//   - Verifier is matched exactly against VSA.Verifier.ID. Required;
//     a VSA with no asserted verifier identity carries very weak
//     trust value, so VerifyVSA returns an error if it is empty.
//   - Levels is OR-matched against VSA.VerifiedLevels — at least one
//     listed level must be satisfied. For canonical SLSA level
//     strings (e.g. SLSA_BUILD_LEVEL_3) the match is "at-or-above":
//     a VSA verifiedLevel of SLSA_BUILD_LEVEL_4 satisfies a want of
//     SLSA_BUILD_LEVEL_3 within the same track. Non-canonical
//     strings only match exactly. Skipped when empty.
//   - Resource and Policy are exact-match against ResourceURI and
//     Policy.URI respectively. Skipped when empty.
//   - Dependencies is AND-matched: every key must appear in
//     VSA.DependencyLevels (count values are not consulted).
//     Skipped when empty.
type VSAOptions struct {
	Verifier     string
	Levels       []string
	Resource     string
	Policy       string
	Dependencies []string
}

// VSAResult is what VerifyVSA returns. VSA is the normalized
// version-neutral predicate; Checks is the per-check outcome in
// display order — exactly the entries needed to render a result
// table for the user.
type VSAResult struct {
	// VSA is the normalized VSA predicate parsed from the envelope.
	// Available to callers that want to display additional fields
	// (e.g. dependency-level counts) alongside the check results.
	VSA *vsa.VSA

	// Checks is the per-check outcome. Always includes the always-on
	// checks (result, verifier); optional checks appear when the
	// corresponding VSAOptions field is non-empty.
	Checks []VSACheck
}

// Pass reports whether every check in the result passed.
func (r *VSAResult) Pass() bool {
	for _, c := range r.Checks {
		if !c.Pass {
			return false
		}
	}
	return true
}

// VSACheck is the result of one hardcoded VSA check.
type VSACheck struct {
	// Name is a human-readable description of what was checked
	// (e.g. `Verifier == "https://verify.example.com"`).
	Name string

	// Pass reports whether the check succeeded.
	Pass bool

	// Message is populated on failure with the observed value
	// (e.g. `verifier.id = "..."`). Empty when Pass is true.
	Message string
}

// VerifyVSA extracts the VSA predicate from env (which must already
// have been signature-verified by the caller — see VerifySignatures),
// converts it to the normalized representation via pkg/slsa/vsa, and
// runs the hardcoded checks selected by opts.
//
// Returns vsa.ErrNotVSA wrapped with the offending predicate type
// when env carries a non-VSA predicate. Always-on checks
// (verificationResult == PASSED and verifier identity match) always
// appear in the result; the optional checks only appear when the
// corresponding VSAOptions field is set.
//
// ctx is accepted for future cancellation/deadline plumbing; the
// current check set is purely in-memory and ignores it.
func (*Verifier) VerifyVSA(_ context.Context, env Envelope, opts *VSAOptions) (*VSAResult, error) {
	if env == nil {
		return nil, errors.New("nil envelope")
	}
	if opts == nil {
		return nil, errors.New("nil VSAOptions")
	}
	if opts.Verifier == "" {
		return nil, errors.New("VSAOptions.Verifier is required")
	}

	stmt := env.GetStatement()
	if stmt == nil {
		return nil, errors.New("envelope produced no statement")
	}
	v, err := vsa.FromStatement(stmt)
	if err != nil {
		if errors.Is(err, vsa.ErrNotVSA) {
			return nil, fmt.Errorf("%w (got %q)", err, stmt.GetPredicateType())
		}
		return nil, fmt.Errorf("extracting VSA: %w", err)
	}

	checks := []VSACheck{
		checkVSAResult(v),
		checkVSAVerifier(v, opts.Verifier),
	}
	if len(opts.Levels) > 0 {
		checks = append(checks, checkVSALevels(v, opts.Levels))
	}
	if opts.Resource != "" {
		checks = append(checks, checkVSAResource(v, opts.Resource))
	}
	if opts.Policy != "" {
		checks = append(checks, checkVSAPolicy(v, opts.Policy))
	}
	if len(opts.Dependencies) > 0 {
		checks = append(checks, checkVSADependencies(v, opts.Dependencies))
	}
	return &VSAResult{VSA: v, Checks: checks}, nil
}

func checkVSAResult(v *vsa.VSA) VSACheck {
	c := VSACheck{Name: "Result is PASSED"}
	if v.Passed() {
		c.Pass = true
		return c
	}
	got := v.VerificationResult
	if got == "" {
		got = "(empty)"
	}
	c.Message = fmt.Sprintf("verificationResult = %s", got)
	return c
}

func checkVSAVerifier(v *vsa.VSA, want string) VSACheck {
	c := VSACheck{Name: fmt.Sprintf("Verifier == %q", want)}
	if v.Verifier.ID == want {
		c.Pass = true
		return c
	}
	c.Message = fmt.Sprintf("verifier.id = %q", v.Verifier.ID)
	return c
}

// checkVSALevels OR-matches the VSA's verifiedLevels against want.
// For canonical SLSA level strings the comparison is at-or-above
// within the same track (see matchesLevel); freeform strings only
// match exactly.
func checkVSALevels(v *vsa.VSA, want []string) VSACheck {
	c := VSACheck{Name: fmt.Sprintf("verifiedLevels satisfies one of %v (or higher per track)", want)}
	for _, w := range want {
		for _, observed := range v.VerifiedLevels {
			if matchesLevel(w, observed) {
				c.Pass = true
				return c
			}
		}
	}
	c.Message = fmt.Sprintf("verifiedLevels = %v", v.VerifiedLevels)
	return c
}

func checkVSAResource(v *vsa.VSA, want string) VSACheck {
	c := VSACheck{Name: fmt.Sprintf("resourceUri == %q", want)}
	if v.ResourceURI == want {
		c.Pass = true
		return c
	}
	c.Message = fmt.Sprintf("resourceUri = %q", v.ResourceURI)
	return c
}

func checkVSAPolicy(v *vsa.VSA, want string) VSACheck {
	c := VSACheck{Name: fmt.Sprintf("policy.uri == %q", want)}
	if v.Policy.URI == want {
		c.Pass = true
		return c
	}
	c.Message = fmt.Sprintf("policy.uri = %q", v.Policy.URI)
	return c
}

// checkVSADependencies enforces that every key in want appears in
// the VSA's dependencyLevels map. Count values are not consulted —
// presence alone is the check. Missing keys are listed in the
// failure message alongside the keys the VSA does report.
func checkVSADependencies(v *vsa.VSA, want []string) VSACheck {
	c := VSACheck{Name: fmt.Sprintf("dependencyLevels contains all of %v", want)}
	var missing []string
	for _, w := range want {
		if _, ok := v.DependencyLevels[w]; !ok {
			missing = append(missing, w)
		}
	}
	if len(missing) == 0 {
		c.Pass = true
		return c
	}
	keys := make([]string, 0, len(v.DependencyLevels))
	for k := range v.DependencyLevels {
		keys = append(keys, k)
	}
	c.Message = fmt.Sprintf("missing %v (have %v)", missing, keys)
	return c
}
