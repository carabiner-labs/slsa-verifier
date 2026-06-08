// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

// addVSA registers the vsa subcommand on parentCmd. The command is a
// stub: it inherits the shared flags from the root command but does
// not yet evaluate Verification Summary Attestations.
func addVSA(parentCmd *cobra.Command, _ *sharedOptions) {
	vsaCmd := &cobra.Command{
		Short: "Verify a SLSA Verification Summary Attestation (VSA)",
		Long: `Verify a SLSA Verification Summary Attestation (VSA).

This subcommand is a stub; VSA verification is not yet implemented.`,
		Use:           "vsa <attestation-path>",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("vsa verification is not yet implemented")
		},
	}
	parentCmd.AddCommand(vsaCmd)
}
