// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/carabiner-dev/collector/envelope"
	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/spf13/cobra"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa"
	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/controls"
)

// officialSourceIssuer and officialSourceSANs identify the official
// SLSA source-actions workflow that signs source provenance
// attestations (the legacy slsa-source-poc SAN is accepted for
// attestations issued before the workflow moved). Verifying against
// them is opt-in via --official.
const officialSourceIssuer = "https://token.actions.githubusercontent.com"

var officialSourceSANs = []string{
	"https://github.com/slsa-framework/source-actions/.github/workflows/compute_slsa_source.yml@refs/heads/main",
	"https://github.com/slsa-framework/slsa-source-poc/.github/workflows/compute_slsa_source.yml@refs/heads/main",
}

// sourceOptions composes the OptionsSets the source command exposes. The
// shared flags (--param, --key, --require-signatures) come from
// sharedOptions registered on the root command, this struct only owns
// the source-specific flags.
type sourceOptions struct {
	shared *sharedOptions

	signingOptions
	controlsOptions
	vsaOutputOptions

	// AttestationPath is the positional argument: path to the attestation
	// file (plain in-toto statement, DSSE envelope, or Sigstore bundle).
	AttestationPath string

	// Level is the raw --level flag: the SLSA source level the
	// attestation is required to reach, as a bare number or a
	// SLSA_SOURCE_LEVEL_N string. Parsed into MinLevel by Validate.
	Level string

	// MinLevel is the parsed required level. Controls above it are
	// informative: they cap the computed level without failing the run.
	MinLevel int

	// Spec is the SLSA spec version whose criteria the attestation is
	// verified against; empty means the latest the catalog defines.
	Spec string

	// ExpectedRepo, ExpectedBranch and ExpectedTag state the expected
	// origin of the revision (spec step 2). They feed the
	// expected_source_repo, expected_branch and expected_tag control
	// params; when unset those checks are skipped.
	ExpectedRepo   string
	ExpectedBranch string
	ExpectedTag    string

	// Since requires every control to have been active since at or
	// before the given date (RFC3339 or YYYY-MM-DD). It feeds the
	// enforced_since control param.
	Since string

	// Official toggles verification against the official SLSA
	// source-actions signing identity. Implies --require-signatures.
	Official bool

	// Verbose toggles inclusion of skipped controls and control titles in
	// the verify summary roster.
	Verbose bool
}

// AddFlags registers the source-specific flags on cmd.
func (o *sourceOptions) AddFlags(cmd *cobra.Command) {
	o.signingOptions.AddFlags(cmd)
	o.controlsOptions.AddFlags(cmd)
	o.vsaOutputOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(
		&o.Level, "level", "1",
		"required SLSA source level (eg 3 or SLSA_SOURCE_LEVEL_3)",
	)
	cmd.PersistentFlags().StringVar(
		&o.Spec, "spec", "",
		"SLSA spec version to verify against (eg 1.2) defaults to the latest",
	)
	cmd.PersistentFlags().StringVar(
		&o.ExpectedRepo, "expected-repo", "",
		"expected repository URI, eg https://github.com/example/repo",
	)
	cmd.PersistentFlags().StringVar(
		&o.ExpectedBranch, "expected-branch", "",
		"expected branch ref, eg refs/heads/main",
	)
	cmd.PersistentFlags().StringVar(
		&o.ExpectedTag, "expected-tag", "",
		"expected tag name (tag provenance only), eg v1.2.3",
	)
	cmd.PersistentFlags().StringVar(
		&o.Since, "since", "",
		"require controls active since at or before this date (RFC3339 or YYYY-MM-DD)",
	)
	cmd.PersistentFlags().BoolVar(
		&o.Official, "official", false,
		"require the attestation to be signed by the official SLSA "+
			"source-actions workflow identity (implies --require-signatures)",
	)
	cmd.PersistentFlags().BoolVarP(
		&o.Verbose, "verbose", "v", false,
		"show skipped controls and control titles in the summary",
	)
}

// Validate runs every option set's validator and propagates implications
// to the shared options struct.
func (o *sourceOptions) Validate() error {
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
	level, err := parseSourceLevel(o.Level)
	if err != nil {
		errs = append(errs, err)
	}
	o.MinLevel = level
	// The expectation flags feed the control params the source catalog
	// reads. They take precedence over an equivalent --param entry.
	if o.ExpectedRepo != "" {
		o.shared.Params["expected_source_repo"] = o.ExpectedRepo
	}
	if o.ExpectedBranch != "" {
		o.shared.Params["expected_branch"] = o.ExpectedBranch
	}
	if o.ExpectedTag != "" {
		// Tag provenance stores the bare tag name, not the full ref.
		o.shared.Params["expected_tag"] = strings.TrimPrefix(o.ExpectedTag, "refs/tags/")
	}
	if o.Since != "" {
		since, sErr := parseSinceDate(o.Since)
		if sErr != nil {
			errs = append(errs, sErr)
		} else {
			o.shared.Params["enforced_since"] = since
		}
	}
	if o.Official {
		for _, san := range officialSourceSANs {
			id, err := sapi.NewIdentityFromSpec(
				fmt.Sprintf("sigstore::%s::%s", officialSourceIssuer, san),
			)
			if err != nil {
				errs = append(errs, fmt.Errorf("building official identity: %w", err))
				continue
			}
			o.Signers = append(o.Signers, id)
		}
	}
	// --signer and --official imply --require-signatures: matching an
	// identity on an unsigned statement is meaningless.
	if len(o.Signers) > 0 {
		o.shared.RequireSignatures = true
	}
	return errors.Join(errs...)
}

// parseSinceDate parses the --since flag value — an RFC3339 timestamp
// or a bare YYYY-MM-DD date — and normalises it to RFC3339 (a bare date
// means midnight UTC) so the CEL timestamp() conversion in the control
// expressions always succeeds.
func parseSinceDate(value string) (string, error) {
	value = strings.TrimSpace(value)
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	if t, err := time.Parse(time.DateOnly, value); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	return "", fmt.Errorf("invalid --since date %q (want RFC3339 or YYYY-MM-DD)", value)
}

// parseSourceLevel parses the --level flag value: a bare number (0-4)
// or a SLSA_SOURCE_LEVEL_N label.
func parseSourceLevel(value string) (int, error) {
	trimmed := strings.TrimPrefix(
		strings.ToUpper(strings.TrimSpace(value)), "SLSA_SOURCE_LEVEL_",
	)
	level, err := strconv.Atoi(trimmed)
	if err != nil || level < 0 || level > maxSourceLevel {
		return 0, fmt.Errorf("invalid source level %q (want 0-%d or SLSA_SOURCE_LEVEL_N)", value, maxSourceLevel)
	}
	return level, nil
}

const maxSourceLevel = 4

// addSource registers the source subcommand on parentCmd.
func addSource(parentCmd *cobra.Command, shared *sharedOptions) {
	opts := &sourceOptions{shared: shared}
	sourceCmd := &cobra.Command{
		Short: "Verify a SLSA source attestation",
		Long: `Verify a SLSA source attestation against the SLSA spec-defined
source-track controls and any user-supplied controls.

The attestation may be supplied as a plain in-toto statement, a DSSE
envelope (signed with one or more keys via --key), or a Sigstore
bundle. Passing --official requires the attestation to be signed by
the official SLSA source-actions workflow.

The verification passes when the attestation reaches the level given
with --level (default 1), controls above it still run and determine
the SLSA source level reported (and emitted with --vsa), but do not
fail the verification.

State your expectations about the origin with --expected-repo and
--expected-branch. --since additionally requires every control to have
been active since at or before that date.

Signer identities (--signer) are spec strings of the form
sigstore::<issuer>::<identity>, matched exactly, or
sigstore(identityMatch=regex)::<issuer>::<identity-regexp>:

  sigstore::https://accounts.google.com::user@example.com
  sigstore(identityMatch=regex)::https://token.actions.githubusercontent.com::.*@example/.*`,
		Use: "source <attestation-path>",
		Example: fmt.Sprintf(
			`%s source --level 3 --official --expected-branch refs/heads/main source-provenance.json`,
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
			return runSource(cmd, opts)
		},
	}
	opts.AddFlags(sourceCmd)
	parentCmd.AddCommand(sourceCmd)
}

func runSource(cmd *cobra.Command, opts *sourceOptions) error {
	keys, err := opts.shared.ParseKeys()
	if err != nil {
		return fmt.Errorf("parsing keys: %w", err)
	}

	// envelope.Parsers handles the format detection (bare in-toto, DSSE,
	// Sigstore bundle) and produces an attestation.Envelope. The
	// pkg/slsa/predicate package's init swap ensures the predicate is
	// parsed with the source-tool proto types.
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
	// is a no-op for them. DSSE uses keys, Sigstore bundles verify
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
		slsa.WithTrack(controls.TrackSource),
		slsa.WithSpecVersion(opts.Spec),
		slsa.WithMinLevel(opts.MinLevel),
		slsa.WithVerifierID(verifierID),
		// There is no buildType concept on the source track: skip the
		// layer so it is not evaluated (or rendered) at all.
		slsa.WithBuildTypeControls(false),
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
		if err := emitVSA(cmd.OutOrStdout(), stmt, result, controls.TrackSource); err != nil {
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
