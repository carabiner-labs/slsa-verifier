// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/collector/envelope"
)

// Load parses a single attestation envelope from path. Format
// auto-detection covers bare in-toto statements, DSSE envelopes,
// and Sigstore bundles; the returned Envelope already has its
// predicate parsed by the SLSA / VSA parser registry the package
// wires up via init().
//
// Returns an error if the file produces zero envelopes or more than
// one (callers wanting a multi-envelope flow should compose
// envelope.Parsers themselves).
func (*Verifier) Load(path string) (Envelope, error) {
	envs, err := envelope.Parsers.ParseFiles([]string{path})
	if err != nil {
		return nil, fmt.Errorf("loading attestation: %w", err)
	}
	if len(envs) == 0 {
		return nil, errors.New("no attestation parsed from file")
	}
	if len(envs) > 1 {
		return nil, fmt.Errorf("expected one attestation, got %d", len(envs))
	}
	return envs[0], nil
}
