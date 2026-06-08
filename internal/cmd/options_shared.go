// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"

	"github.com/carabiner-dev/command/keys"
	"github.com/spf13/cobra"
)

// sharedOptions aggregates the flags every verifier subcommand
// (build, vsa, source) exposes: --param, --key, and
// --require-signatures. They are registered as persistent flags on
// the root command so each subcommand reads the same parsed values.
type sharedOptions struct {
	paramOptions
	keys.Options

	// RequireSignatures, when true, fails verification if the statement
	// is unsigned or its signature did not verify.
	RequireSignatures bool
}

func (so *sharedOptions) AddFlags(cmd *cobra.Command) {
	so.paramOptions.AddFlags(cmd)
	so.Options.AddFlags(cmd)
	cmd.PersistentFlags().BoolVar(
		&so.RequireSignatures, "require-signatures", false,
		"fail verification if the statement is unsigned or its signature did not verify",
	)
}

func (so *sharedOptions) Validate() error {
	return errors.Join(
		so.paramOptions.Validate(),
		so.Options.Validate(),
	)
}
