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
)

// A public key that did not sign the fixture.
const wrongKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq0F7Qy812rYgbwi5c1wSnevN8FEC
hDjayw2lL6wkyR9k1vWICQYbe4FqOZeulBbfWBU7/BKdtlwKRStEVEffvg==
-----END PUBLIC KEY-----`

// testdata/forged-vsa.dsse.json is a PASSED VSA for verifier.id
// https://verify.example.com at SLSA_BUILD_LEVEL_4, wrapped in a DSSE
// envelope signed with a throwaway key nobody has: a well-formed
// signature that no supplied key will ever verify.
// testdata/garbage-sig-vsa.dsse.json is the same VSA with signature
// bytes that are not a signature at all.
func TestRunVSASignatureOutcomes(t *testing.T) {
	t.Parallel()

	keyPath := filepath.Join(t.TempDir(), "wrong.pem")
	require.NoError(t, os.WriteFile(keyPath, []byte(wrongKeyPEM), 0o600))

	for _, tc := range []struct {
		name       string
		fixture    string // defaults to forged-vsa.dsse.json
		required   bool
		keyPaths   []string
		wantErr    error  // sentinel the error must wrap; nil means success
		wantExec   bool   // true: an execution error (exit 2), not ErrVerifyFailed
		wantOutput string // substring expected on stdout
		wantMsg    string // substring expected in the error
	}{
		{
			name:       "not required: forged signature is ignored, VSA passes",
			wantOutput: "PASS",
		},
		{
			name:     "required, no key: unverifiable is an execution error",
			required: true, wantExec: true, wantMsg: "--key",
		},
		{
			name:     "required, wrong key: did not verify is a FAIL",
			required: true, keyPaths: []string{keyPath},
			wantErr: ErrVerifyFailed, wantOutput: "did not verify",
		},
		{
			// Bytes that are not a signature are a bad signature, not a
			// tooling problem: the key was supplied and the check ran.
			name:    "required, key supplied, garbage signature bytes: FAIL, not an error",
			fixture: "garbage-sig-vsa.dsse.json", required: true, keyPaths: []string{keyPath},
			wantErr: ErrVerifyFailed, wantOutput: "did not verify",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			shared := &sharedOptions{RequireSignatures: tc.required}
			shared.PublicKeyPaths = tc.keyPaths
			opts := &vsaOptions{
				shared:          shared,
				Verifier:        "https://verify.example.com",
				Levels:          []string{"SLSA_BUILD_LEVEL_3"},
				AttestationPath: filepath.Join("testdata", "forged-vsa.dsse.json"),
			}
			if tc.fixture != "" {
				opts.AttestationPath = filepath.Join("testdata", tc.fixture)
			}
			var out bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&out)

			err := runVSA(cmd, opts)
			if tc.wantOutput != "" {
				assert.Contains(t, out.String(), tc.wantOutput)
			}
			switch {
			case tc.wantExec:
				require.Error(t, err)
				require.NotErrorIs(t, err, ErrVerifyFailed, "must not be reported as a verification failure")
				assert.Contains(t, err.Error(), tc.wantMsg)
			case tc.wantErr != nil:
				require.ErrorIs(t, err, tc.wantErr)
			default:
				require.NoError(t, err)
			}
		})
	}
}
