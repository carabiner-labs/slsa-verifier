// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package predicate registers SLSA-only attestation.PredicateParser
// implementations as the collector's global predicate parser registry.
//
// Importing this package replaces github.com/carabiner-dev/collector's
// shipped predicate parser map (which covers SBOMs, VEX, OSV, …) with the
// SLSA build (v0.1, v0.2, v1.0) and SLSA source predicate types only,
// using the upstream proto definitions from
// github.com/in-toto/attestation/go/predicates/provenance and
// github.com/slsa-framework/source-tool/pkg/provenance.
package predicate

import (
	"fmt"
	"strings"

	"github.com/carabiner-dev/attestation"
	collectorpred "github.com/carabiner-dev/collector/predicate"
	"github.com/carabiner-dev/collector/predicate/generic"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/eval"
)

// Parser handles a single SLSA predicate type by unmarshalling JSON into
// the upstream proto message registered for that type in the eval package.
type Parser struct {
	predicateType attestation.PredicateType
}

// NewParser returns a Parser for the given SLSA predicate type. The type
// must be registered in the eval package; otherwise NewParser returns nil
// and false.
func NewParser(predicateType attestation.PredicateType) (*Parser, bool) {
	if !eval.IsKnownPredicateType(string(predicateType)) {
		return nil, false
	}
	return &Parser{predicateType: predicateType}, true
}

// Parse unmarshals data into the proto message backing this parser's
// predicate type and wraps it in a generic.Predicate so the collector
// can thread it through statements and envelopes. After unmarshalling,
// nil singular sub-messages are replaced with zero-valued instances so
// CEL expressions can chain through intermediate fields without
// erroring on missing payload data.
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	msg, _ := eval.NewPredicate(string(p.predicateType))
	if err := protojson.Unmarshal(data, msg); err != nil {
		if isWrongFormat(err) {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("parsing %s predicate: %w", p.predicateType, err)
	}
	eval.FillNilMessages(msg)
	return &generic.Predicate{
		Type:   p.predicateType,
		Parsed: msg,
		Data:   data,
	}, nil
}

// SupportsType reports whether this parser handles any of types.
func (p *Parser) SupportsType(types ...attestation.PredicateType) bool {
	for _, t := range types {
		if t == p.predicateType {
			return true
		}
	}
	return false
}

// isWrongFormat translates protojson "doesn't match this proto" errors
// into the collector's ErrNotCorrectFormat sentinel so its parser dispatch
// keeps trying the remaining parsers instead of bubbling up.
func isWrongFormat(err error) bool {
	s := err.Error()
	return strings.Contains(s, "syntax error") ||
		strings.Contains(s, "unknown field") ||
		strings.Contains(s, "invalid value")
}

// Parsers is the SLSA-only predicate parser registry — one Parser per
// predicate type known to the eval package.
var Parsers = func() collectorpred.ParsersList {
	out := collectorpred.ParsersList{}
	for _, pt := range eval.KnownPredicateTypes() {
		p, _ := NewParser(attestation.PredicateType(pt))
		out[attestation.PredicateType(pt)] = p
	}
	return out
}()

// init replaces the collector's global predicate parser registry with the
// SLSA-only set above. After this package is imported (directly or
// transitively), envelope.Parsers and statement.Parsers parse predicates
// through this package only.
func init() {
	collectorpred.Parsers = Parsers
}
