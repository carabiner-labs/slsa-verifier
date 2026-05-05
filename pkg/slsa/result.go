// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

// Status enumerates the high-level outcome of a verification or a single control.
type Status string

const (
	// StatusPass means the verification or control evaluation succeeded.
	StatusPass Status = "PASS"

	// StatusFail means the verification or control evaluation failed.
	StatusFail Status = "FAIL"

	// StatusError means the control evaluation produced an error during evaluation
	// (distinct from a clean false outcome).
	StatusError Status = "ERROR"
)

// ControlResult captures the outcome of evaluating a single control.
type ControlResult struct {
	ID      string
	Title   string
	Status  Status
	Message string
}

// Result is the final verification outcome returned to callers.
type Result struct {
	// Status is the aggregate outcome derived from all evaluated controls.
	Status Status

	// SLSALevel is the highest SLSA level whose required core controls all passed.
	SLSALevel int

	// CoreResults holds per-control results for the SLSA spec-defined controls.
	CoreResults []*ControlResult

	// BuildTypeResults holds per-control results for custom buildType controls.
	BuildTypeResults []*ControlResult

	// UserResults holds per-control results for user-supplied controls.
	UserResults []*ControlResult
}

// Pass reports whether the result is a PASS.
func (r *Result) Pass() bool {
	return r != nil && r.Status == StatusPass
}
