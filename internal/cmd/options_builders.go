// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/builders"
)

// builderOptions holds the flags that bind builders to the identities
// signing their provenance: bindings given on the command line and a
// registry file extending the embedded one.
type builderOptions struct {
	// BuilderSpecs holds the raw --builder values, "id=signer-spec" or
	// "id=issuer".
	BuilderSpecs []string

	// RegistryPath is a registry file or directory (--builders) merged
	// over the embedded registry.
	RegistryPath string

	// registry is the merged registry, nil when nothing extends the
	// embedded one. Populated by Validate.
	registry *builders.Registry
}

func (o *builderOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringArrayVar(
		&o.BuilderSpecs, "builder", nil,
		"builder bound to the identity signing its provenance, as id=<signer spec> or "+
			"id=<OIDC issuer> (repeatable; extends the embedded registry)",
	)
	cmd.PersistentFlags().StringVar(
		&o.RegistryPath, "builders", "",
		"YAML file or directory of builder bindings, merged over the embedded registry",
	)
}

// Validate parses the bindings and loads the registry file, building
// the merged registry when either was given.
func (o *builderOptions) Validate() error {
	if len(o.BuilderSpecs) == 0 && o.RegistryPath == "" {
		o.registry = nil
		return nil
	}
	reg, err := builders.LoadEmbedded()
	if err != nil {
		return fmt.Errorf("loading the embedded builder registry: %w", err)
	}
	var errs []error
	if o.RegistryPath != "" {
		custom, err := builders.Load(o.RegistryPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("--builders: %w", err))
		} else if err := reg.Merge(custom); err != nil {
			errs = append(errs, fmt.Errorf("--builders: %w", err))
		}
	}
	for _, raw := range o.BuilderSpecs {
		b, err := builders.ParseBinding(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("--builder: %w", err))
			continue
		}
		if err := reg.Add(b); err != nil {
			errs = append(errs, fmt.Errorf("--builder %q: %w", raw, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	o.registry = reg
	return nil
}

// Registry returns the merged builder registry, or nil to use the
// embedded one.
func (o *builderOptions) Registry() *builders.Registry {
	return o.registry
}
