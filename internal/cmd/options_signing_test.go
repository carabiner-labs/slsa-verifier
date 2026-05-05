// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSigningOptionsParsesSignerSpec(t *testing.T) {
	t.Parallel()

	so := &signingOptions{
		SignerSpecs: []string{
			"sigstore::https://accounts.google.com::user@example.com",
		},
	}
	require.NoError(t, so.Validate())
	require.Len(t, so.Signers, 1)
	assert.NotNil(t, so.Signers[0].GetSigstore())
	assert.Equal(t, "user@example.com", so.Signers[0].GetSigstore().GetIdentity())
}

func TestSigningOptionsImpliesRequireSignatures(t *testing.T) {
	t.Parallel()

	so := &signingOptions{
		SignerSpecs: []string{
			"sigstore::https://accounts.google.com::user@example.com",
		},
	}
	require.NoError(t, so.Validate())
	assert.True(t, so.RequireSignatures, "--signer should imply --require-signatures")
}

func TestSigningOptionsAccumulatesSigners(t *testing.T) {
	t.Parallel()

	so := &signingOptions{
		SignerSpecs: []string{
			"sigstore::https://accounts.google.com::a@example.com",
			"sigstore::https://accounts.google.com::b@example.com",
		},
	}
	require.NoError(t, so.Validate())
	assert.Len(t, so.Signers, 2)
}

func TestSigningOptionsMalformedSpecErrors(t *testing.T) {
	t.Parallel()

	so := &signingOptions{
		SignerSpecs: []string{"this-is-not-a-spec"},
	}
	err := so.Validate()
	assert.Error(t, err)
}

func TestSigningOptionsNoSignerLeavesRequireSignaturesUntouched(t *testing.T) {
	t.Parallel()

	so := &signingOptions{}
	require.NoError(t, so.Validate())
	assert.False(t, so.RequireSignatures)
	assert.Empty(t, so.Signers)
}
