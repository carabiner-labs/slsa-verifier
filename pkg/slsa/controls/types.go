// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package controls

import (
	"errors"
	"fmt"
)

// Control models a single verification control: a labelled bundle of CEL
// checks, each pinned to a specific predicate type.
type Control struct {
	ID          string  `yaml:"id"`
	Title       string  `yaml:"title"`
	Description string  `yaml:"description,omitempty"`
	SLSALevel   int     `yaml:"slsaLevel,omitempty"`
	Checks      []Check `yaml:"checks"`
}

// Check binds a CEL expression to a specific in-toto predicate type along
// with the names of parameters the expression expects to find on `params`.
type Check struct {
	PredicateType string   `yaml:"predicateType"`
	Expression    string   `yaml:"expression"`
	Parameters    []string `yaml:"parameters,omitempty"`
}

// Validate checks the control's structural integrity.
func (c *Control) Validate() error {
	var errs []error
	if c.ID == "" {
		errs = append(errs, errors.New("control: id is required"))
	}
	if c.Title == "" {
		errs = append(errs, fmt.Errorf("control %q: title is required", c.ID))
	}
	if len(c.Checks) == 0 {
		errs = append(errs, fmt.Errorf("control %q: at least one check is required", c.ID))
	}
	for i := range c.Checks {
		if err := c.Checks[i].Validate(); err != nil {
			errs = append(errs, fmt.Errorf("control %q check #%d: %w", c.ID, i, err))
		}
	}
	return errors.Join(errs...)
}

// Validate checks the check's structural integrity.
func (c *Check) Validate() error {
	var errs []error
	if c.PredicateType == "" {
		errs = append(errs, errors.New("predicateType is required"))
	}
	if c.Expression == "" {
		errs = append(errs, errors.New("expression is required"))
	}
	return errors.Join(errs...)
}
