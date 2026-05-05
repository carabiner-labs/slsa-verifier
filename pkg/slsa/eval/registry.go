// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package eval

import (
	provenancev01 "github.com/in-toto/attestation/go/predicates/provenance/v01"
	provenancev02 "github.com/in-toto/attestation/go/predicates/provenance/v02"
	provenancev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	sourceprovenance "github.com/slsa-framework/source-tool/pkg/provenance"
	"google.golang.org/protobuf/proto"
)

// SLSA predicate type URIs supported by the verifier.
const (
	PredicateProvenanceV01    = "https://slsa.dev/provenance/v0.1"
	PredicateProvenanceV02    = "https://slsa.dev/provenance/v0.2"
	PredicateProvenanceV1     = "https://slsa.dev/provenance/v1"
	PredicateSourceProvenance = sourceprovenance.SourceProvPredicateType
)

// Track names a SLSA spec track. Each registered predicate type belongs
// to exactly one track, and every Control declares the track it
// targets — load-time validation ensures the two stay in sync.
type Track string

const (
	TrackBuild  Track = "build"
	TrackSource Track = "source"
)

// PredicateFactory returns an empty proto.Message of the matching predicate type.
type PredicateFactory func() proto.Message

// predicateRegistration carries the per-predicate data the verifier
// needs: which track it belongs to and how to allocate an empty
// instance for parsing/CEL registration.
type predicateRegistration struct {
	Track   Track
	Factory PredicateFactory
}

// registeredPredicates maps predicate-type URIs to their track + proto
// factory. The factories are used to register descriptors with cel.Env
// and (for the CLI's verify path) to parse predicate payloads.
var registeredPredicates = map[string]predicateRegistration{
	PredicateProvenanceV01: {
		Track:   TrackBuild,
		Factory: func() proto.Message { return &provenancev01.Provenance{} },
	},
	PredicateProvenanceV02: {
		Track:   TrackBuild,
		Factory: func() proto.Message { return &provenancev02.Provenance{} },
	},
	PredicateProvenanceV1: {
		Track:   TrackBuild,
		Factory: func() proto.Message { return &provenancev1.Provenance{} },
	},
	PredicateSourceProvenance: {
		Track:   TrackSource,
		Factory: func() proto.Message { return &sourceprovenance.SourceProvenancePred{} },
	},
}

// IsKnownPredicateType reports whether the given URI matches a SLSA
// predicate type the verifier supports.
func IsKnownPredicateType(uri string) bool {
	_, ok := registeredPredicates[uri]
	return ok
}

// TrackOf returns the SLSA spec track for a predicate type URI, or the
// empty string if the URI isn't registered.
func TrackOf(uri string) Track {
	if r, ok := registeredPredicates[uri]; ok {
		return r.Track
	}
	return ""
}

// KnownPredicateTypes returns the list of supported predicate-type URIs.
func KnownPredicateTypes() []string {
	out := make([]string, 0, len(registeredPredicates))
	for k := range registeredPredicates {
		out = append(out, k)
	}
	return out
}

// NewPredicate returns an empty proto.Message for the given predicate type
// or false if the type is unknown.
func NewPredicate(predicateType string) (proto.Message, bool) {
	r, ok := registeredPredicates[predicateType]
	if !ok {
		return nil, false
	}
	return r.Factory(), true
}
