// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/command"
	"github.com/carabiner-dev/command/keys"
	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = &signingOptions{}

// signingOptions wraps the carabiner keys OptionsSet (--key/-k) and adds
// the verifier's signature-related flags: --require-signatures and
// --signer (repeatable, takes a signer/api/v1 spec string).
type signingOptions struct {
	keys.Options

	config *command.OptionsSetConfig

	// RequireSignatures, when true, fails verification if the statement
	// is unsigned or its signature did not verify.
	RequireSignatures bool

	// SignerSpecs is the raw --signer flag values from the command line.
	SignerSpecs []string

	// Signers is the parsed signer-identity list (one *sapi.Identity per
	// --signer flag). Populated by Validate.
	Signers []*sapi.Identity
}

func (so *signingOptions) Config() *command.OptionsSetConfig {
	if so.config == nil {
		so.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				"require-signatures": {
					Long: "require-signatures",
					Help: "fail verification if the statement is unsigned or its signature did not verify",
				},
				"signer": {
					Long: "signer",
					Help: "expected signer identity as a spec string (repeatable; OR matched). " +
						"Implies --require-signatures. Examples: " +
						"'sigstore::https://accounts.google.com::user@example.com', " +
						"'sigstore(identityMatch=regex)::https://token.actions.githubusercontent.com::.*@example/.*'",
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
	cmd.PersistentFlags().StringArrayVar(
		&so.SignerSpecs,
		so.Config().LongFlag("signer"),
		nil,
		so.Config().HelpText("signer"),
	)
}

func (so *signingOptions) Validate() error {
	if err := so.Options.Validate(); err != nil {
		return err
	}
	errs := []error{}
	for _, spec := range so.SignerSpecs {
		id, err := sapi.NewIdentityFromSpec(spec)
		if err != nil {
			errs = append(errs, fmt.Errorf("parsing --signer %q: %w", spec, err))
			continue
		}
		so.Signers = append(so.Signers, id)
	}
	// --signer implies --require-signatures: matching an identity on an
	// unsigned statement is meaningless.
	if len(so.Signers) > 0 {
		so.RequireSignatures = true
	}
	return errors.Join(errs...)
}
