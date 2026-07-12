// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSourceLevel(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		value   string
		want    int
		wantErr bool
	}{
		{"0", 0, false},
		{"1", 1, false},
		{"4", 4, false},
		{"SLSA_SOURCE_LEVEL_3", 3, false},
		{"slsa_source_level_2", 2, false},
		{" 2 ", 2, false},
		{"5", 0, true},
		{"-1", 0, true},
		{"", 0, true},
		{"SLSA_BUILD_LEVEL_3", 0, true},
		{"three", 0, true},
	} {
		got, err := parseSourceLevel(tc.value)
		if tc.wantErr {
			assert.Error(t, err, "value %q", tc.value)
			continue
		}
		require.NoError(t, err, "value %q", tc.value)
		assert.Equal(t, tc.want, got, "value %q", tc.value)
	}
}

func TestSourceOptionsOfficialAddsIdentities(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "att.json")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))

	opts := &sourceOptions{
		shared:          &sharedOptions{},
		AttestationPath: path,
		Level:           "1",
		Official:        true,
	}
	require.NoError(t, opts.Validate())
	assert.Len(t, opts.Signers, 2, "official flag should add both known SANs")
	assert.True(t, opts.shared.RequireSignatures, "official implies --require-signatures")
	assert.Equal(t, 1, opts.MinLevel)
}

func TestSourceOptionsValidateLevel(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "att.json")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))

	opts := &sourceOptions{
		shared:          &sharedOptions{},
		AttestationPath: path,
		Level:           "SLSA_SOURCE_LEVEL_4",
	}
	require.NoError(t, opts.Validate())
	assert.Equal(t, 4, opts.MinLevel)
	assert.Empty(t, opts.Signers)
	assert.False(t, opts.shared.RequireSignatures)

	opts = &sourceOptions{
		shared:          &sharedOptions{},
		AttestationPath: path,
		Level:           "9",
	}
	assert.Error(t, opts.Validate())
}
