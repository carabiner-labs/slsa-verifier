// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// verifyOptions composes every OptionsSet needed by the verify command.
type verifyOptions struct {
	paramOptions

	// AttestationPath is the positional argument: path to the attestation
	// (in-toto JSON statement, DSSE envelope, or sigstore bundle).
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

The attestation may be supplied as a plain in-toto statement, a DSSE
envelope, or a Sigstore bundle.`,
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

			// Phase 4b will replace this placeholder with statement
			// loading via the collector and a Verifier.Verify call.
			fmt.Printf("Would verify %s\n", opts.AttestationPath)
			if len(opts.Params) > 0 {
				fmt.Println("Parameters:")
				for k, v := range opts.Params {
					fmt.Printf("  %s = %v\n", k, v)
				}
			}
			return nil
		},
	}
	opts.AddFlags(verifyCmd)
	parentCmd.AddCommand(verifyCmd)
}
