// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/carabiner-dev/collector/envelope"
	"github.com/spf13/cobra"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa"
	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/controls"
)

// verifyOptions composes every OptionsSet needed by the verify command.
type verifyOptions struct {
	paramOptions
	signingOptions
	controlsOptions

	// AttestationPath is the positional argument: path to the attestation
	// file (plain in-toto statement, DSSE envelope, or Sigstore bundle).
	AttestationPath string

	// Verbose toggles inclusion of skipped controls and control titles in
	// the verify summary roster.
	Verbose bool

	// Track selects the SLSA track to evaluate against. "auto" (default)
	// asks the verifier to derive the track from the catalog; "build" or
	// "source" force the track regardless of the predicate's classification.
	Track string
}

// AddFlags registers all option sets on the verify command.
func (o *verifyOptions) AddFlags(cmd *cobra.Command) {
	o.paramOptions.AddFlags(cmd)
	o.signingOptions.AddFlags(cmd)
	o.controlsOptions.AddFlags(cmd)
	cmd.PersistentFlags().BoolVarP(
		&o.Verbose, "verbose", "v", false,
		"show skipped controls and control titles in the summary",
	)
	cmd.PersistentFlags().StringVar(
		&o.Track, "track", "auto",
		`SLSA track to evaluate against ("auto", "build", or "source")`,
	)
}

// Validate runs every option set's validator.
func (o *verifyOptions) Validate() error {
	errs := []error{
		o.paramOptions.Validate(),
		o.signingOptions.Validate(),
		o.controlsOptions.Validate(),
	}
	if o.AttestationPath == "" {
		errs = append(errs, errors.New("attestation path is required"))
	} else if _, err := os.Stat(o.AttestationPath); err != nil {
		errs = append(errs, fmt.Errorf("attestation file: %w", err))
	}
	switch o.Track {
	case "auto", string(controls.TrackBuild), string(controls.TrackSource):
	default:
		errs = append(errs, fmt.Errorf(
			`invalid --track %q (want "auto", %q, or %q)`,
			o.Track, controls.TrackBuild, controls.TrackSource,
		))
	}
	return errors.Join(errs...)
}

// forcedTrack maps the CLI flag value to the verifier's ForceTrack
// option: "auto" (or empty) → empty (auto resolution); track names pass
// through.
func (o *verifyOptions) forcedTrack() controls.Track {
	if o.Track == "" || o.Track == "auto" {
		return ""
	}
	return controls.Track(o.Track)
}

// addVerify registers the verify subcommand on parentCmd.
func addVerify(parentCmd *cobra.Command) {
	opts := &verifyOptions{}
	verifyCmd := &cobra.Command{
		Short: "Verify a SLSA attestation",
		Long: `Verify a SLSA build or source attestation against the SLSA
spec-defined controls and any user-supplied controls.

The attestation may be supplied as a plain in-toto statement, a DSSE
envelope (signed with one or more keys via --key), or a Sigstore
bundle.`,
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
	keys, err := opts.ParseKeys()
	if err != nil {
		return fmt.Errorf("parsing keys: %w", err)
	}

	// envelope.Parsers handles format detection (bare in-toto, DSSE,
	// Sigstore bundle) and produces an attestation.Envelope. The
	// pkg/slsa/predicate package's init swap ensures the predicate is
	// parsed with the upstream SLSA proto types.
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

	// Verify envelope signatures. Bare envelopes are unsigned and Verify
	// is a no-op for them; DSSE uses keys; Sigstore bundles verify
	// against the embedded trust root.
	if err := env.Verify(keys); err != nil {
		return fmt.Errorf("verifying envelope signatures: %w", err)
	}

	stmt := env.GetStatement()
	if stmt == nil {
		return errors.New("envelope produced no statement")
	}

	v, err := slsa.New()
	if err != nil {
		return fmt.Errorf("building verifier: %w", err)
	}

	result, err := v.Verify(
		cmd.Context(),
		stmt,
		slsa.WithParams(opts.Params),
		slsa.WithRequireSignatures(opts.RequireSignatures),
		slsa.WithExpectedSigners(opts.Signers),
		slsa.WithUserControlList(opts.Controls),
		slsa.WithTrack(opts.forcedTrack()),
	)
	// Signature / identity failures from the verification layer are a
	// verification outcome (exit 1), not an execution failure (exit 2).
	if errors.Is(err, slsa.ErrSignatureRequired) {
		writef(cmd.OutOrStdout(), "FAIL\n  Signature: %s\n", err)
		return ErrVerifyFailed
	}
	if errors.Is(err, slsa.ErrIdentityMismatch) {
		writef(cmd.OutOrStdout(), "FAIL\n  Identity: %s\n", err)
		return ErrVerifyFailed
	}
	if err != nil {
		return fmt.Errorf("running verification: %w", err)
	}

	printResult(cmd.OutOrStdout(), result, opts.Verbose)
	if !result.Pass() {
		return ErrVerifyFailed
	}
	return nil
}

// writef wraps Fprintf and discards the result — terminal output failures
// are not actionable in this context.
//
//nolint:errcheck // best-effort summary print
func writef(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, format, args...)
}
