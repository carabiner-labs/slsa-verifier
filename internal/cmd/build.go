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

// buildOptions composes every OptionsSet needed by the build command.
// The shared flags (--param, --key, --require-signatures) come from
// sharedOptions registered on the root command, this struct only owns
// the build-specific flags.
type buildOptions struct {
	shared *sharedOptions

	signingOptions
	controlsOptions
	vsaOutputOptions

	// AttestationPath is the positional argument: path to the attestation
	// file (plain in-toto statement, DSSE envelope, or Sigstore bundle).
	AttestationPath string

	// Spec is the SLSA spec version whose criteria the attestation is
	// verified against, empty means the latest the catalog defines.
	Spec string

	// Verbose toggles inclusion of skipped controls and control titles in
	// the verify summary roster.
	Verbose bool
}

// AddFlags registers the build-specific flags on cmd.
func (o *buildOptions) AddFlags(cmd *cobra.Command) {
	o.signingOptions.AddFlags(cmd)
	o.controlsOptions.AddFlags(cmd)
	o.vsaOutputOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(
		&o.Spec, "spec", "",
		"SLSA spec version to verify against (eg 1.2) defaults to latest",
	)
	cmd.PersistentFlags().BoolVarP(
		&o.Verbose, "verbose", "v", false,
		"show skipped controls and control titles in the summary",
	)
}

// Validate runs every option set's validator and propagates implications
// to the shared options struct.
func (o *buildOptions) Validate() error {
	errs := []error{
		o.shared.Validate(),
		o.signingOptions.Validate(),
		o.controlsOptions.Validate(),
		o.vsaOutputOptions.Validate(),
	}
	if o.AttestationPath == "" {
		errs = append(errs, errors.New("attestation path is required"))
	} else if _, err := os.Stat(o.AttestationPath); err != nil {
		errs = append(errs, fmt.Errorf("attestation file: %w", err))
	}
	// --signer implies --require-signatures: matching an identity on an
	// unsigned statement is meaningless.
	if len(o.Signers) > 0 {
		o.shared.RequireSignatures = true
	}
	return errors.Join(errs...)
}

// addBuild registers the build subcommand on parentCmd.
func addBuild(parentCmd *cobra.Command, shared *sharedOptions) {
	opts := &buildOptions{shared: shared}
	buildCmd := &cobra.Command{
		Short: "Verify a SLSA build attestation",
		Long: `Verify a SLSA build attestation against the SLSA spec-defined
build-track controls and any user-supplied controls.

The attestation may be supplied as a plain in-toto statement, a DSSE
envelope (signed with one or more keys via --key), or a Sigstore
bundle.

Signer identities (--signer) are spec strings of the form
sigstore::<issuer>::<identity>, matched exactly, or
sigstore(identityMatch=regex)::<issuer>::<identity-regexp>:

  sigstore::https://accounts.google.com::user@example.com
  sigstore(identityMatch=regex)::https://token.actions.githubusercontent.com::.*@example/.*`,
		Use: "build <attestation-path>",
		Example: fmt.Sprintf(
			`%s build --param=expected_source:git+https://example.com/repo provenance.intoto.json`,
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
			return runBuild(cmd, opts)
		},
	}
	opts.AddFlags(buildCmd)
	parentCmd.AddCommand(buildCmd)
}

func runBuild(cmd *cobra.Command, opts *buildOptions) error {
	keys, err := opts.shared.ParseKeys()
	if err != nil {
		return fmt.Errorf("parsing keys: %w", err)
	}

	// envelope.Parsers handles the format detection (bare in-toto, DSSE,
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
	// is a no-op for them. DSSE uses keys and Sigstore bundles verify
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
		slsa.WithParams(opts.shared.Params),
		slsa.WithRequireSignatures(opts.shared.RequireSignatures),
		slsa.WithExpectedSigners(opts.Signers),
		slsa.WithUserControlList(opts.Controls),
		slsa.WithTrack(controls.TrackBuild),
		slsa.WithSpecVersion(opts.Spec),
		slsa.WithVerifierID(opts.VerifierID),
	)
	// Signature/identity failures from the verification layer are a
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

	// With --vsa, stdout carries the unsigned VSA JSON instead of the
	// human-readable roster so it can be piped or stored directly.
	if opts.EmitVSA {
		if err := emitVSA(cmd.OutOrStdout(), stmt, result, controls.TrackBuild); err != nil {
			return fmt.Errorf("emitting VSA: %w", err)
		}
	} else {
		printResult(cmd.OutOrStdout(), result, opts.Verbose)
	}
	if !result.Pass() {
		return ErrVerifyFailed
	}
	return nil
}

// writef wraps Fprintf and discards the result
func writef(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, format, args...) //nolint:errcheck
}
