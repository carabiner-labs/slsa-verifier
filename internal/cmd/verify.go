// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa"
	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/predicate"
)

// verifyOptions composes every OptionsSet needed by the verify command.
type verifyOptions struct {
	paramOptions

	// AttestationPath is the positional argument: path to the attestation
	// (currently a plain in-toto JSON statement; DSSE / Sigstore bundle
	// support lands later).
	AttestationPath string
}

// AddFlags registers all option sets on the verify command.
func (o *verifyOptions) AddFlags(cmd *cobra.Command) {
	o.paramOptions.AddFlags(cmd)
}

// Validate runs every option set's validator.
func (o *verifyOptions) Validate() error {
	errs := []error{
		o.paramOptions.Validate(),
	}
	if o.AttestationPath == "" {
		errs = append(errs, errors.New("attestation path is required"))
	} else if _, err := os.Stat(o.AttestationPath); err != nil {
		errs = append(errs, fmt.Errorf("attestation file: %w", err))
	}
	return errors.Join(errs...)
}

// addVerify registers the verify subcommand on parentCmd.
func addVerify(parentCmd *cobra.Command) {
	opts := &verifyOptions{}
	verifyCmd := &cobra.Command{
		Short: "Verify a SLSA attestation",
		Long: `Verify a SLSA build or source attestation against the SLSA
spec-defined controls and any user-supplied controls.

The attestation may be supplied as a plain in-toto statement. DSSE
envelope and Sigstore bundle support are planned.`,
		Use: "verify <attestation-path>",
		Example: fmt.Sprintf(
			`%s verify --param=expected_source:git+https://example.com/repo provenance.intoto.json`,
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
			return runVerify(cmd, opts)
		},
	}
	opts.AddFlags(verifyCmd)
	parentCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, opts *verifyOptions) error {
	stmt, err := predicate.LoadStatement(opts.AttestationPath)
	if err != nil {
		return fmt.Errorf("loading attestation: %w", err)
	}

	v, err := slsa.New()
	if err != nil {
		return fmt.Errorf("building verifier: %w", err)
	}

	result, err := v.Verify(cmd.Context(), stmt, slsa.WithParams(opts.Params))
	if err != nil {
		return fmt.Errorf("running verification: %w", err)
	}

	printResult(cmd.OutOrStdout(), result)
	if !result.Pass() {
		return ErrVerifyFailed
	}
	return nil
}

// printResult writes a minimal pass/fail summary. More elaborate output
// formats (JSON, VSA, etc.) will be introduced later.
func printResult(w io.Writer, result *slsa.Result) {
	if result.Pass() {
		writef(w, "PASS\n")
		if result.SLSALevel > 0 {
			writef(w, "SLSA Level: %d\n", result.SLSALevel)
		}
		return
	}

	writef(w, "FAIL\n")
	printFailures(w, "Core", result.CoreResults)
	printFailures(w, "BuildType", result.BuildTypeResults)
	printFailures(w, "User", result.UserResults)
}

func printFailures(w io.Writer, label string, results []*slsa.ControlResult) {
	for _, cr := range results {
		if cr.Status == slsa.StatusPass {
			continue
		}
		writef(w, "  [%s] %s (%s) — %s", label, cr.ID, cr.Status, cr.Title)
		if cr.Message != "" {
			writef(w, ": %s", cr.Message)
		}
		writef(w, "\n")
	}
}

// writef wraps Fprintf and discards the result — terminal output failures
// are not actionable in this context.
//
//nolint:errcheck // best-effort summary print
func writef(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, format, args...)
}
