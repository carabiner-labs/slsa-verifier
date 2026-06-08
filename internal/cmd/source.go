// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

// addSource registers the source subcommand on parentCmd. The command
// is a stub: it inherits the shared flags from the root command but
// does not yet evaluate SLSA source attestations.
func addSource(parentCmd *cobra.Command, _ *sharedOptions) {
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
	parentCmd.AddCommand(sourceCmd)
}
