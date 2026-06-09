// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
)

// vsaOutputOptions is the OptionsSet shared by the verifier subcommands
// (build and source) that can summarise their own evaluation as a SLSA
// Verification Summary Attestation. When EmitVSA is set, the command
// writes an unsigned VSA carrying the computed SLSA level to stdout
// instead of the human-readable control roster.
type vsaOutputOptions struct {
	// EmitVSA toggles emission of an unsigned VSA to stdout (--vsa).
	EmitVSA bool
}

func (o *vsaOutputOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(
		&o.EmitVSA, "vsa", false,
		"emit an unsigned Verification Summary Attestation (VSA) with the "+
			"computed SLSA level to stdout instead of the verification roster",
	)
}

func (o *vsaOutputOptions) Validate() error { return nil }
