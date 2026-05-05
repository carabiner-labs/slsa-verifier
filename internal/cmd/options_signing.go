// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/carabiner-dev/command"
	"github.com/carabiner-dev/command/keys"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = &signingOptions{}

// signingOptions wraps the carabiner keys OptionsSet (--key/-k) and adds
// a --require-signatures toggle for the verifier. Identity-matching flags
// (--identity, --issuer, …) will land in a follow-up.
type signingOptions struct {
	keys.Options

	config *command.OptionsSetConfig

	// RequireSignatures, when true, fails verification if the statement
	// is unsigned or its signature did not verify.
	RequireSignatures bool
}

func (so *signingOptions) Config() *command.OptionsSetConfig {
	if so.config == nil {
		so.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				"require-signatures": {
					Long: "require-signatures",
					Help: "fail verification if the statement is unsigned or its signature did not verify",
				},
			},
		}
	}
	return so.config
}

func (so *signingOptions) AddFlags(cmd *cobra.Command) {
	so.Options.AddFlags(cmd)
	cmd.PersistentFlags().BoolVar(
		&so.RequireSignatures,
		so.Config().LongFlag("require-signatures"),
		false,
		so.Config().HelpText("require-signatures"),
	)
}

func (so *signingOptions) Validate() error {
	return so.Options.Validate()
}
