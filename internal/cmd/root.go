// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Exit codes the CLI uses for the verify subcommand.
const (
	ExitOK              = 0
	ExitVerifyFailed    = 1
	ExitExecutionFailed = 2
)

// ErrVerifyFailed signals that the verifier ran successfully but the
// attestation did not pass. Returning it from RunE causes Execute to exit
// with ExitVerifyFailed without printing the usual "Error:" prefix.
var ErrVerifyFailed = errors.New("attestation verification failed")

const appname = "slsa-verifier"

var rootCmd = &cobra.Command{
	Short: fmt.Sprintf("%s: verify SLSA build and source attestations", appname),
	Long: fmt.Sprintf(`
%s verifies SLSA build attestations (v0.1, v0.2, v1.0) and SLSA source
attestations against the SLSA spec-defined controls and any user-supplied
controls.
`, appname),
	Use:           appname,
	SilenceUsage:  false,
	SilenceErrors: true,
}

// Execute runs the CLI. The CLI translates verifier outcomes to exit
// codes: 0 for pass, 1 for verification failure, 2 for execution errors.
func Execute() {
	shared := &sharedOptions{}
	shared.AddFlags(rootCmd)
	addBuild(rootCmd, shared)
	addVSA(rootCmd, shared)
	addSource(rootCmd, shared)
	if err := rootCmd.Execute(); err != nil {
		if errors.Is(err, ErrVerifyFailed) {
			os.Exit(ExitVerifyFailed)
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(ExitExecutionFailed)
	}
}
