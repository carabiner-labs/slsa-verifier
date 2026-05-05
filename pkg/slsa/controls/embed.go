// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package controls

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa/eval"
)

//go:embed catalog
var catalogFS embed.FS

const catalogRoot = "catalog"

// Category groups controls by their location in the embedded catalog tree.
// The string value matches the relative directory under catalogRoot.
type Category string

const (
	// BuildCore groups SLSA spec-defined controls applied to build provenance.
	BuildCore Category = "build/core"

	// BuildType groups custom controls keyed to specific build types.
	BuildType Category = "build/buildType"

	// SourceCore groups SLSA spec-defined controls applied to SLSA source attestations.
	SourceCore Category = "source/core"
)

// Catalog is a loaded set of controls grouped by category.
//
// predicateTracks is the predicate-type → track mapping assembled at
// load time by walking every control's checks. Each predicate type is
// associated with whatever track its first encountering control
// declared; the loader rejects a catalog where the same predicate type
// appears under more than one track. Future versions will allow
// multi-track predicates (e.g. a VSA applicable to both build and
// source) — for now it's a hard error so misclassified controls are
// caught early.
type Catalog struct {
	Controls        map[Category][]*Control
	predicateTracks map[string]Track
}

// Get returns the controls registered under the given category. Safe to call
// on a nil receiver and on missing categories — returns nil in both cases.
func (c *Catalog) Get(cat Category) []*Control {
	if c == nil {
		return nil
	}
	return c.Controls[cat]
}

// TrackOf returns the track associated with the given predicate-type URI
// in this catalog, or the empty string if the URI is not referenced by
// any loaded control.
func (c *Catalog) TrackOf(predicateType string) Track {
	if c == nil {
		return ""
	}
	return c.predicateTracks[predicateType]
}

// LoadEmbedded loads the controls compiled into the binary.
func LoadEmbedded() (*Catalog, error) {
	return loadFromFS(catalogFS, catalogRoot)
}

// loadFromFS walks the directory rooted at root in fsys and parses every
// YAML file found. Each file's location relative to root determines the
// category its controls are placed under. After parsing, the
// predicate-track mapping is assembled by walking every loaded control;
// a predicate type appearing under more than one track produces a load
// error.
func loadFromFS(fsys fs.FS, root string) (*Catalog, error) {
	cat := &Catalog{
		Controls:        map[Category][]*Control{},
		predicateTracks: map[string]Track{},
	}

	walkErr := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			return nil
		}

		category := categoryFromPath(root, p)
		data, readErr := fs.ReadFile(fsys, p)
		if readErr != nil {
			return fmt.Errorf("reading %s: %w", p, readErr)
		}
		ctrls, parseErr := parseYAML(data)
		if parseErr != nil {
			return fmt.Errorf("parsing %s: %w", p, parseErr)
		}
		for _, ctrl := range ctrls {
			if vErr := ctrl.Validate(); vErr != nil {
				return fmt.Errorf("invalid control in %s: %w", p, vErr)
			}
			if vErr := validateTrack(ctrl); vErr != nil {
				return fmt.Errorf("invalid control in %s: %w", p, vErr)
			}
		}
		cat.Controls[category] = append(cat.Controls[category], ctrls...)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	if err := assemblePredicateTracks(cat); err != nil {
		return nil, err
	}
	return cat, nil
}

// assemblePredicateTracks walks every loaded control and builds the
// predicate-type → track map on the catalog. A predicate type that
// surfaces under more than one track is rejected — callers should split
// their controls or wait for the multi-track relaxation.
func assemblePredicateTracks(cat *Catalog) error {
	flat := make([]*Control, 0)
	for _, byCategory := range cat.Controls {
		flat = append(flat, byCategory...)
	}
	tracks, err := buildPredicateTracks(flat)
	if err != nil {
		return err
	}
	cat.predicateTracks = tracks
	return nil
}

// buildPredicateTracks walks ctrls and returns the predicate-type →
// track mapping. Any predicate that appears under more than one track
// produces an error — multi-track predicates aren't supported yet.
// Used both for the embedded catalog assembly and for user-supplied
// control sets loaded via Load.
func buildPredicateTracks(ctrls []*Control) (map[string]Track, error) {
	out := map[string]Track{}
	owners := map[string]string{} // predicate → first control id seen for the existing track
	for _, ctrl := range ctrls {
		track := Track(ctrl.Track)
		for _, ck := range ctrl.Checks {
			if existing, seen := out[ck.PredicateType]; seen {
				if existing != track {
					return nil, fmt.Errorf(
						"predicate type %q has conflicting tracks %q (control %q) and %q (control %q) — multi-track predicates are not supported yet",
						ck.PredicateType, existing, owners[ck.PredicateType], track, ctrl.ID,
					)
				}
				continue
			}
			out[ck.PredicateType] = track
			owners[ck.PredicateType] = ctrl.ID
		}
	}
	return out, nil
}

// categoryFromPath returns the directory of file relative to root, used as
// the Category key.
func categoryFromPath(root, file string) Category {
	rel := strings.TrimPrefix(file, root)
	rel = strings.TrimPrefix(rel, "/")
	return Category(path.Dir(rel))
}

// validateTrack performs the per-control track checks: the track must
// be a known value, and every check's predicateType must be registered
// in the eval package (so we have a proto to parse it into and a CEL
// env to run against). Cross-control track consistency happens at the
// catalog level via assemblePredicateTracks.
func validateTrack(c *Control) error {
	track := Track(c.Track)
	switch track {
	case TrackBuild, TrackSource:
	default:
		return fmt.Errorf("control %q: track must be %q or %q (got %q)",
			c.ID, TrackBuild, TrackSource, c.Track)
	}
	for i, ck := range c.Checks {
		if !eval.IsKnownPredicateType(ck.PredicateType) {
			return fmt.Errorf("control %q check #%d: predicateType %q is not a registered SLSA predicate",
				c.ID, i, ck.PredicateType)
		}
	}
	return nil
}

// parseYAML decodes a multi-document YAML stream into a slice of controls.
// Empty documents (e.g. trailing `---` markers) are skipped.
func parseYAML(data []byte) ([]*Control, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []*Control
	for {
		var c Control
		if err := dec.Decode(&c); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if c.ID == "" && c.Title == "" && len(c.Checks) == 0 {
			continue
		}
		out = append(out, &c)
	}
	return out, nil
}
