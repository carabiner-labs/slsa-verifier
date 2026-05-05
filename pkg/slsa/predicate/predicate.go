// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package predicate implements an attestation.Predicate / Statement that
// only recognises SLSA build (v0.1, v0.2, v1.0) and SLSA source predicate
// types. The set of recognised types is sourced from the eval package
// registry so predicate parsing and CEL evaluation stay in lockstep.
package predicate

import (
	"errors"
	"fmt"
	"os"

	"github.com/carabiner-dev/attestation"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/eval"
)

// ErrUnsupportedPredicate is returned when the statement's predicate
// type is not one of the SLSA build or source types.
var ErrUnsupportedPredicate = errors.New("predicate: only SLSA build and source predicate types are supported")

// Predicate is the SLSA-restricted implementation of attestation.Predicate.
type Predicate struct {
	Type         attestation.PredicateType
	Parsed       proto.Message
	Data         []byte
	Origin       attestation.Subject
	Verification attestation.Verification
}

var _ attestation.Predicate = (*Predicate)(nil)

func (p *Predicate) GetType() attestation.PredicateType { return p.Type }

func (p *Predicate) SetType(t attestation.PredicateType) error {
	p.Type = t
	return nil
}

func (p *Predicate) GetParsed() any                             { return p.Parsed }
func (p *Predicate) GetData() []byte                            { return p.Data }
func (p *Predicate) GetOrigin() attestation.Subject             { return p.Origin }
func (p *Predicate) SetOrigin(s attestation.Subject)            { p.Origin = s }
func (p *Predicate) GetVerification() attestation.Verification  { return p.Verification }
func (p *Predicate) SetVerification(v attestation.Verification) { p.Verification = v }

// Statement is the SLSA-restricted implementation of attestation.Statement.
// It wraps an in-toto v1 Statement plus our typed Predicate.
type Statement struct {
	Stmt *intoto.Statement
	Pred *Predicate
}

var _ attestation.Statement = (*Statement)(nil)

func (s *Statement) GetSubjects() []attestation.Subject {
	subs := s.Stmt.GetSubject()
	out := make([]attestation.Subject, len(subs))
	for i, sub := range subs {
		out[i] = sub
	}
	return out
}

func (s *Statement) GetPredicate() attestation.Predicate         { return s.Pred }
func (s *Statement) GetPredicateType() attestation.PredicateType { return s.Pred.GetType() }
func (s *Statement) GetType() string                             { return s.Stmt.GetType() }
func (s *Statement) GetVerification() attestation.Verification {
	if s.Pred == nil {
		return nil
	}
	return s.Pred.Verification
}

// ParsePredicate parses raw predicate JSON for the given predicate type.
// Returns ErrUnsupportedPredicate if the type isn't a SLSA build or source
// type registered in the eval package.
func ParsePredicate(predicateType attestation.PredicateType, data []byte) (*Predicate, error) {
	msg, ok := eval.NewPredicate(string(predicateType))
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedPredicate, predicateType)
	}
	if err := protojson.Unmarshal(data, msg); err != nil {
		return nil, fmt.Errorf("unmarshalling predicate JSON: %w", err)
	}
	return &Predicate{
		Type:   predicateType,
		Parsed: msg,
		Data:   data,
	}, nil
}

// ParseStatement parses a plain in-toto JSON Statement payload and returns
// a Statement with the predicate parsed into the matching SLSA proto type.
// Returns ErrUnsupportedPredicate if the predicateType isn't a SLSA build
// or source type.
func ParseStatement(data []byte) (*Statement, error) {
	istmt := &intoto.Statement{}
	if err := protojson.Unmarshal(data, istmt); err != nil {
		return nil, fmt.Errorf("unmarshalling statement: %w", err)
	}
	pt := istmt.GetPredicateType()
	if pt == "" {
		return nil, errors.New("statement has empty predicateType")
	}

	predBytes, err := protojson.Marshal(istmt.GetPredicate())
	if err != nil {
		return nil, fmt.Errorf("marshalling inner predicate: %w", err)
	}
	pred, err := ParsePredicate(attestation.PredicateType(pt), predBytes)
	if err != nil {
		return nil, err
	}
	return &Statement{Stmt: istmt, Pred: pred}, nil
}

// LoadStatement reads a plain in-toto JSON Statement from path and parses
// it. DSSE envelopes and Sigstore bundles are rejected at this layer; a
// later phase will add envelope detection in front of this call.
func LoadStatement(path string) (*Statement, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading attestation file: %w", err)
	}
	return ParseStatement(data)
}
