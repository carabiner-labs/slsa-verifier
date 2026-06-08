// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/carabiner-labs/slsa-verifier/pkg/attestation"
)

// vsaOptions composes the flags specific to the vsa subcommand. The
// shared flags (--key, --param, --require-signatures) come from
// sharedOptions registered on the root command. --signer and the
// other build-only flags are intentionally NOT exposed here; if a
// future iteration needs them on the VSA path they can be lifted to
// sharedOptions.
type vsaOptions struct {
	shared *sharedOptions

	Verifier     string
	Levels       []string
	Resource     string
	Policy       string
	Dependencies []string

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
	cmd.PersistentFlags().StringArrayVar(
		&o.Dependencies, "dependency", nil,
		"expected dependencyLevels key (repeatable; AND-matched — every entry must appear in the map)",
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

// toLibOptions converts the CLI flag struct to the library's
// VSAOptions. Kept as a tiny adapter so the CLI flag layer can evolve
// independently of the library's public option fields.
func (o *vsaOptions) toLibOptions() attestation.VSAOptions {
	return attestation.VSAOptions{
		Verifier:     o.Verifier,
		Levels:       o.Levels,
		Resource:     o.Resource,
		Policy:       o.Policy,
		Dependencies: o.Dependencies,
	}
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
  * policy.uri must equal --policy (if set)
  * dependencyLevels must contain every --dependency key (if any given)`,
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

	v := attestation.New()
	env, err := v.Load(opts.AttestationPath)
	if err != nil {
		return err
	}
	if err := v.VerifySignatures(env, attestation.SignatureOptions{
		Keys:     keys,
		Required: opts.shared.RequireSignatures,
	}); err != nil {
		if errors.Is(err, attestation.ErrSignatureRequired) {
			writef(cmd.OutOrStdout(), "%s\n  Signature: %s\n", redf("FAIL"), err)
			return ErrVerifyFailed
		}
		return err
	}

	result, err := v.VerifyVSA(cmd.Context(), env, opts.toLibOptions())
	if err != nil {
		return err
	}
	printVSAResult(cmd.OutOrStdout(), result)
	if !result.Pass() {
		return ErrVerifyFailed
	}
	return nil
}

// formatDependencyLevels renders a dependencyLevels map as
// "LEVEL=count, …" with keys in sorted order so the output is stable
// across runs.
func formatDependencyLevels(m map[string]uint64) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// printVSAResult writes the PASS/FAIL header, a summary of the VSA's
// key fields, and the table of check outcomes. Format mirrors the
// build subcommand's printer so user-facing output stays consistent.
func printVSAResult(w io.Writer, result *attestation.VSAResult) {
	v := result.VSA
	if result.Pass() {
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
	if len(v.DependencyLevels) > 0 {
		writef(tw, "  Dependencies:\t%s\n", formatDependencyLevels(v.DependencyLevels))
	}
	flushTabWriter(tw)
	writef(w, "\n")

	writef(w, "Checks:\n")
	ct := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, c := range result.Checks {
		line := fmt.Sprintf("  %s\t%s", vsaCheckMarker(c.Pass), c.Name)
		if !c.Pass && c.Message != "" {
			line += "\t" + dimf(c.Message)
		}
		writef(ct, "%s\n", line)
	}
	flushTabWriter(ct)
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
