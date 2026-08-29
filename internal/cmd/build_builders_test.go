// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa"
)

// A key-signed build attestation from a builder the registry does not
// know is refused with the flags that bind it, accepted unproven with
// --allow-unbound-builder, and bound with --builder id=<key spec>.
func TestRunBuildBuilderBinding(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	k := newSigningKey(t, dir, "ci")
	payload, err := os.ReadFile(filepath.Join("..", "..", "pkg", "slsa", "testdata", "plain", "v1-build.intoto.json"))
	require.NoError(t, err)
	attestationPath := signDSSE(t, dir, "provenance", payload, k)

	run := func(t *testing.T, configure func(*buildOptions)) (string, error) {
		t.Helper()
		shared := &sharedOptions{}
		shared.Raw = []string{"expected_source:git+https://example.com/repo", "trusted_builders:[https://example.com/builder]"}
		shared.PublicKeyPaths = []string{k.pemPath}
		opts := &buildOptions{shared: shared, AttestationPath: attestationPath, Verbose: true}
		configure(opts)
		require.NoError(t, opts.Validate())
		var out bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&out)
		err := runBuild(cmd, opts)
		return out.String(), err
	}

	t.Run("unbound builder is refused", func(t *testing.T) {
		t.Parallel()
		_, err := run(t, func(*buildOptions) {})
		require.ErrorIs(t, err, slsa.ErrBuilderUnbound)
		assert.Contains(t, err.Error(), "--builder https://example.com/builder=")
		assert.Contains(t, err.Error(), "--allow-unbound-builder")
		assert.Contains(t, err.Error(), k.spec, "the error names who signed")
	})

	t.Run("allowed unbound builder passes unproven", func(t *testing.T) {
		t.Parallel()
		out, err := run(t, func(o *buildOptions) { o.AllowUnbound = true })
		require.NoError(t, err)
		assert.Contains(t, out, "[SKIP]  L2  builder-identity-bound")
	})

	t.Run("bound builder passes", func(t *testing.T) {
		t.Parallel()
		out, err := run(t, func(o *buildOptions) {
			o.BuilderSpecs = []string{"https://example.com/builder=" + k.spec}
		})
		require.NoError(t, err)
		assert.Contains(t, out, "[PASS]  L2  builder-identity-bound")
	})

	t.Run("builder bound to another key fails", func(t *testing.T) {
		t.Parallel()
		other := newSigningKey(t, dir, "other")
		out, err := run(t, func(o *buildOptions) {
			o.BuilderSpecs = []string{"https://example.com/builder=" + other.spec}
		})
		require.ErrorIs(t, err, ErrVerifyFailed)
		assert.Contains(t, out, "[FAIL]  L2  builder-identity-bound")
	})
}
