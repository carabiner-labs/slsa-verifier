// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/carabiner-dev/collector/envelope"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/vsa"
)

// vsaOptions composes the flags specific to the vsa subcommand. The
// shared flags (--key, --param, --require-signatures) come from
// sharedOptions registered on the root command. --signer and the
// other build-only flags are intentionally NOT exposed here; if a
// future iteration needs them on the VSA path they can be lifted to
// sharedOptions.
type vsaOptions struct {
	shared *sharedOptions

	// Verifier is matched exactly against the VSA's verifier.id field.
	// Required: a VSA without an attributed verifier offers very weak
	// trust value.
	Verifier string

	// Levels, when non-empty, are OR-matched against the VSA's
	// verifiedLevels (v1) or PolicyLevel folded into a single-element
	// list (v0.2). At least one entry must appear in the VSA.
	Levels []string

	// Resource, when set, must equal the VSA's resourceUri field.
	Resource string

	// Policy, when set, must equal the VSA's policy.uri field.
	Policy string

	// AttestationPath is the positional argument: path to the VSA
	// envelope file (plain in-toto statement, DSSE, or Sigstore bundle).
	AttestationPath string
}

func (o *vsaOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(
		&o.Verifier, "verifier", "",
		"expected verifier.id (required; exact match)",
	)
	cmd.PersistentFlags().StringArrayVar(
		&o.Levels, "level", nil,
		"expected verifiedLevels entry (repeatable; OR-matched — at least one must appear)",
	)
	cmd.PersistentFlags().StringVar(
		&o.Resource, "resource", "",
		"expected resourceUri (exact match; skipped if empty)",
	)
	cmd.PersistentFlags().StringVar(
		&o.Policy, "policy", "",
		"expected policy.uri (exact match; skipped if empty)",
	)
}

func (o *vsaOptions) Validate() error {
	errs := []error{o.shared.Validate()}
	if o.Verifier == "" {
		errs = append(errs, errors.New("--verifier is required"))
	}
	if o.AttestationPath == "" {
		errs = append(errs, errors.New("attestation path is required"))
	} else if _, err := os.Stat(o.AttestationPath); err != nil {
		errs = append(errs, fmt.Errorf("attestation file: %w", err))
	}
	return errors.Join(errs...)
}

// addVSA registers the vsa subcommand on parentCmd.
func addVSA(parentCmd *cobra.Command, shared *sharedOptions) {
	opts := &vsaOptions{shared: shared}
	vsaCmd := &cobra.Command{
		Short: "Verify a SLSA Verification Summary Attestation (VSA)",
		Long: `Verify a SLSA Verification Summary Attestation (VSA, v0.2 or v1).

The VSA's envelope signature is verified using --key (and optionally
--require-signatures). The predicate is then converted to a
version-neutral representation and the following checks run:

  * verificationResult must be "PASSED" (always enforced)
  * verifier.id must equal --verifier (always enforced)
  * verifiedLevels must contain at least one of --level (if any --level given)
  * resourceUri must equal --resource (if set)
  * policy.uri must equal --policy (if set)`,
		Use: "vsa <attestation-path>",
		Example: fmt.Sprintf(
			`%s vsa --verifier https://verify.example.com --level SLSA_BUILD_LEVEL_3 vsa.intoto.json`,
			appname,
		),
		SilenceUsage:  false,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		PreRunE: func(_ *cobra.Command, args []string) error {
			opts.AttestationPath = args[0]
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}
			cmd.SilenceUsage = true
			return runVSA(cmd, opts)
		},
	}
	opts.AddFlags(vsaCmd)
	parentCmd.AddCommand(vsaCmd)
}

func runVSA(cmd *cobra.Command, opts *vsaOptions) error {
	keys, err := opts.shared.ParseKeys()
	if err != nil {
		return fmt.Errorf("parsing keys: %w", err)
	}

	envs, err := envelope.Parsers.ParseFiles([]string{opts.AttestationPath})
	if err != nil {
		return fmt.Errorf("loading attestation: %w", err)
	}
	if len(envs) == 0 {
		return errors.New("no attestation parsed from file")
	}
	if len(envs) > 1 {
		return fmt.Errorf("expected one attestation, got %d", len(envs))
	}
	env := envs[0]

	if err := env.Verify(keys); err != nil {
		return fmt.Errorf("verifying envelope signatures: %w", err)
	}
	if opts.shared.RequireSignatures && len(env.GetSignatures()) == 0 {
		writef(cmd.OutOrStdout(), "%s\n  Signature: statement is unsigned and --require-signatures was set\n", redf("FAIL"))
		return ErrVerifyFailed
	}

	stmt := env.GetStatement()
	if stmt == nil {
		return errors.New("envelope produced no statement")
	}

	v, err := vsa.FromStatement(stmt)
	if err != nil {
		if errors.Is(err, vsa.ErrNotVSA) {
			return fmt.Errorf("%w (got %q)", err, stmt.GetPredicateType())
		}
		return fmt.Errorf("extracting VSA: %w", err)
	}

	checks := runVSAChecks(v, opts)
	printVSAResult(cmd.OutOrStdout(), v, checks)
	for _, c := range checks {
		if !c.pass {
			return ErrVerifyFailed
		}
	}
	return nil
}

// vsaCheck is the result of one hardcoded VSA check.
type vsaCheck struct {
	name    string
	pass    bool
	message string // populated on failure; describes got vs want
}

// runVSAChecks applies every hardcoded VSA check that is in scope for
// opts (skipping optional checks whose flag is empty). Results are
// returned in display order.
func runVSAChecks(v *vsa.VSA, opts *vsaOptions) []vsaCheck {
	checks := []vsaCheck{
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
	return checks
}

func checkVSAResult(v *vsa.VSA) vsaCheck {
	c := vsaCheck{name: "Result is PASSED"}
	if v.Passed() {
		c.pass = true
		return c
	}
	got := v.VerificationResult
	if got == "" {
		got = "(empty)"
	}
	c.message = fmt.Sprintf("verificationResult = %s", got)
	return c
}

func checkVSAVerifier(v *vsa.VSA, want string) vsaCheck {
	c := vsaCheck{name: fmt.Sprintf("Verifier == %q", want)}
	if v.Verifier.ID == want {
		c.pass = true
		return c
	}
	c.message = fmt.Sprintf("verifier.id = %q", v.Verifier.ID)
	return c
}

func checkVSALevels(v *vsa.VSA, want []string) vsaCheck {
	c := vsaCheck{name: fmt.Sprintf("verifiedLevels matches one of %v", want)}
	for _, w := range want {
		if slices.Contains(v.VerifiedLevels, w) {
			c.pass = true
			return c
		}
	}
	c.message = fmt.Sprintf("verifiedLevels = %v", v.VerifiedLevels)
	return c
}

func checkVSAResource(v *vsa.VSA, want string) vsaCheck {
	c := vsaCheck{name: fmt.Sprintf("resourceUri == %q", want)}
	if v.ResourceURI == want {
		c.pass = true
		return c
	}
	c.message = fmt.Sprintf("resourceUri = %q", v.ResourceURI)
	return c
}

func checkVSAPolicy(v *vsa.VSA, want string) vsaCheck {
	c := vsaCheck{name: fmt.Sprintf("policy.uri == %q", want)}
	if v.Policy.URI == want {
		c.pass = true
		return c
	}
	c.message = fmt.Sprintf("policy.uri = %q", v.Policy.URI)
	return c
}

// printVSAResult writes the PASS/FAIL header, a summary of the VSA's
// key fields, and the table of check outcomes. Format mirrors the
// build subcommand's printer so user-facing output stays consistent.
func printVSAResult(w io.Writer, v *vsa.VSA, checks []vsaCheck) {
	if allChecksPassed(checks) {
		writef(w, "%s\n", greenf("PASS"))
	} else {
		writef(w, "%s\n", redf("FAIL"))
	}
	writef(w, "VSA: %s\n", v.PredicateType)
	writef(w, "\n")

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	writef(tw, "  Verifier:\t%s\n", v.Verifier.ID)
	writef(tw, "  Result:\t%s\n", v.VerificationResult)
	if v.ResourceURI != "" {
		writef(tw, "  Resource:\t%s\n", v.ResourceURI)
	}
	if v.Policy.URI != "" {
		writef(tw, "  Policy:\t%s\n", v.Policy.URI)
	}
	if len(v.VerifiedLevels) > 0 {
		writef(tw, "  Levels:\t%s\n", strings.Join(v.VerifiedLevels, ", "))
	}
	flushTabWriter(tw)
	writef(w, "\n")

	writef(w, "Checks:\n")
	ct := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, c := range checks {
		line := fmt.Sprintf("  %s\t%s", vsaCheckMarker(c.pass), c.name)
		if !c.pass && c.message != "" {
			line += "\t" + dimf(c.message)
		}
		writef(ct, "%s\n", line)
	}
	flushTabWriter(ct)
}

func allChecksPassed(checks []vsaCheck) bool {
	for _, c := range checks {
		if !c.pass {
			return false
		}
	}
	return true
}

// vsaCheckMarker mirrors statusMarker but for the boolean pass/fail
// shape used by VSA checks.
func vsaCheckMarker(pass bool) string {
	if color.NoColor {
		if pass {
			return "[PASS]"
		}
		return "[FAIL]"
	}
	if pass {
		return color.GreenString("✓")
	}
	return color.RedString("✗")
}
