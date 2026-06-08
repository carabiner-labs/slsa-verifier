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
// signature list and Verify hook, so signature tests can drive both
// the cryptographic path (env.Verify error) and the policy path
// (Required-but-unsigned) without colliding with vsa_test.go's
// fakeEnvelope behaviour.
type signedEnvelope struct {
	*fakeEnvelope
	verifyErr error
}

func (e *signedEnvelope) Verify(_ ...any) error { return e.verifyErr }

func newSignedEnv(sigs []cdattestation.Signature, verifyErr error) *signedEnvelope {
	return &signedEnvelope{
		fakeEnvelope: &fakeEnvelope{sigs: sigs},
		verifyErr:    verifyErr,
	}
}

// fakeSignature is the smallest Signature implementation needed to
// make len(GetSignatures()) non-zero.
type fakeSignature struct{}

func (fakeSignature) GetKeyid() string { return "test-keyid" }
func (fakeSignature) GetSig() []byte   { return []byte("sig") }

func TestVerifySignaturesNilEnvelope(t *testing.T) {
	t.Parallel()

	err := New().VerifySignatures(nil, SignatureOptions{})
	require.Error(t, err)
}

func TestVerifySignaturesRequiredAndUnsigned(t *testing.T) {
	t.Parallel()

	env := newSignedEnv(nil, nil) // no sigs, Verify returns nil
	err := New().VerifySignatures(env, SignatureOptions{Required: true})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSignatureRequired),
		"expected ErrSignatureRequired, got %v", err)
}

func TestVerifySignaturesRequiredAndSigned(t *testing.T) {
	t.Parallel()

	env := newSignedEnv([]cdattestation.Signature{fakeSignature{}}, nil)
	err := New().VerifySignatures(env, SignatureOptions{Required: true})
	assert.NoError(t, err)
}

func TestVerifySignaturesNotRequiredAndUnsigned(t *testing.T) {
	t.Parallel()

	env := newSignedEnv(nil, nil)
	err := New().VerifySignatures(env, SignatureOptions{Required: false})
	assert.NoError(t, err, "unsigned envelope must pass when Required=false")
}

func TestVerifySignaturesPropagatesEnvelopeError(t *testing.T) {
	t.Parallel()

	want := errors.New("bad signature")
	env := newSignedEnv([]cdattestation.Signature{fakeSignature{}}, want)
	err := New().VerifySignatures(env, SignatureOptions{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, want), "expected wrapped envelope error, got %v", err)
}
