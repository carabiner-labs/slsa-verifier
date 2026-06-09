// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

// sourceOptions composes the OptionsSets the source command exposes. The
// shared flags (--param, --key, --require-signatures) come from
// sharedOptions registered on the root command; vsaOutputOptions is the
// same --vsa flag the build command uses, so a future source verifier can
// emit a VSA from its evaluation through the shared output path.
type sourceOptions struct {
	shared *sharedOptions

	vsaOutputOptions
}

func (o *sourceOptions) AddFlags(cmd *cobra.Command) {
	o.vsaOutputOptions.AddFlags(cmd)
}

func (o *sourceOptions) Validate() error {
	return errors.Join(
		o.shared.Validate(),
		o.vsaOutputOptions.Validate(),
	)
}

// addSource registers the source subcommand on parentCmd. The command
// inherits the shared flags from the root command and exposes the shared
// --vsa output flag, but does not yet evaluate SLSA source attestations.
func addSource(parentCmd *cobra.Command, shared *sharedOptions) {
	opts := &sourceOptions{shared: shared}
	sourceCmd := &cobra.Command{
		Short: "Verify a SLSA source attestation",
		Long: `Verify a SLSA source attestation against the SLSA spec-defined
source-track controls and any user-supplied controls.

This subcommand is a stub; source verification is not yet implemented.`,
		Use:           "source <attestation-path>",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("source verification is not yet implemented")
		},
	}
	opts.AddFlags(sourceCmd)
	parentCmd.AddCommand(sourceCmd)
}
