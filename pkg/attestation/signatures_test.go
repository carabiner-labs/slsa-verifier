// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"errors"
	"testing"

	cdattestation "github.com/carabiner-dev/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signedEnvelope is a fakeEnvelope flavour with a configurable
// signature list, verification result and Verify hook, so signature
// tests can drive the cryptographic path (env.Verify error), the
// recorded-result path (GetVerification) and the policy path
// (Required) without colliding with vsa_test.go's fakeEnvelope
// behaviour.
type signedEnvelope struct {
	*fakeEnvelope
	ver       cdattestation.Verification
	verifyErr error
}

func (e *signedEnvelope) GetVerification() cdattestation.Verification { return e.ver }
func (e *signedEnvelope) Verify(_ ...any) error                       { return e.verifyErr }

func newSignedEnv(sigs []cdattestation.Signature, ver cdattestation.Verification, verifyErr error) *signedEnvelope {
	return &signedEnvelope{
		fakeEnvelope: &fakeEnvelope{sigs: sigs},
		ver:          ver,
		verifyErr:    verifyErr,
	}
}

// fakeSignature is the smallest Signature implementation needed to
// make len(GetSignatures()) non-zero.
type fakeSignature struct{}

func (fakeSignature) GetKeyid() string { return "test-keyid" }
func (fakeSignature) GetSig() []byte   { return []byte("sig") }

var oneSig = []cdattestation.Signature{fakeSignature{}}

func TestVerifySignaturesNilEnvelope(t *testing.T) {
	t.Parallel()

	err := New().VerifySignatures(nil, SignatureOptions{})
	require.Error(t, err)
}

func TestVerifySignaturesRequired(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		sigs    []cdattestation.Signature
		ver     cdattestation.Verification
		wantErr error
	}{
		{
			name: "unsigned",
			sigs: nil, ver: nil,
			wantErr: ErrSignatureRequired,
		},
		{
			// An envelope that claims to be verified but carries no
			// signatures is still unsigned; the signature check wins.
			name: "unsigned with stray verification",
			sigs: nil, ver: &fakeVerification{verified: true},
			wantErr: ErrSignatureRequired,
		},
		{
			// Signature present, Verify returned nil, but nothing
			// recorded a verified result: no key material was given.
			name: "signed without verification result",
			sigs: oneSig, ver: nil,
			wantErr: ErrSignatureUnverified,
		},
		{
			// Signature present, Verify returned nil, and the envelope
			// recorded a failed verification as a result rather than
			// an error (collector DSSE envelope behaviour).
			name: "signed but verification failed",
			sigs: oneSig, ver: &fakeVerification{verified: false},
			wantErr: ErrSignatureUnverified,
		},
		{
			name: "signed and verified",
			sigs: oneSig, ver: &fakeVerification{verified: true},
			wantErr: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newSignedEnv(tc.sigs, tc.ver, nil)
			err := New().VerifySignatures(env, SignatureOptions{Required: true})
			if tc.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.wantErr, "expected %v, got %v", tc.wantErr, err)
		})
	}
}

func TestVerifySignaturesNotRequired(t *testing.T) {
	t.Parallel()

	// With Required=false a missing or negative signal is not an
	// error: only a failure reported by Verify itself is.
	for _, tc := range []struct {
		name string
		sigs []cdattestation.Signature
		ver  cdattestation.Verification
	}{
		{name: "unsigned", sigs: nil, ver: nil},
		{name: "signed without verification result", sigs: oneSig, ver: nil},
		{name: "signed but verification failed", sigs: oneSig, ver: &fakeVerification{verified: false}},
		{name: "signed and verified", sigs: oneSig, ver: &fakeVerification{verified: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newSignedEnv(tc.sigs, tc.ver, nil)
			err := New().VerifySignatures(env, SignatureOptions{Required: false})
			assert.NoError(t, err)
		})
	}
}

func TestVerifySignaturesPropagatesEnvelopeError(t *testing.T) {
	t.Parallel()

	want := errors.New("bad signature")
	for _, required := range []bool{false, true} {
		env := newSignedEnv(oneSig, &fakeVerification{verified: true}, want)
		err := New().VerifySignatures(env, SignatureOptions{Required: required})
		require.Error(t, err)
		require.ErrorIs(t, err, want, "required=%v: expected wrapped envelope error, got %v", required, err)
		require.NotErrorIs(t, err, ErrSignatureRequired)
		require.NotErrorIs(t, err, ErrSignatureUnverified)
	}
}
