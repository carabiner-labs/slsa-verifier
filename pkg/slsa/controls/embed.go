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
// PredicateTracks is the predicate-type → tracks mapping assembled at
// load time by walking every control's checks. A predicate type may
// appear under more than one track (e.g. a VSA applicable to both
// build and source); when that happens, the verifier requires the
// caller to disambiguate via VerificationOptions.ForceTrack. Exported
// so tests can construct synthetic catalogs.
type Catalog struct {
	Controls        map[Category][]*Control
	PredicateTracks map[string][]Track
}

// Get returns the controls registered under the given category. Safe to call
// on a nil receiver and on missing categories — returns nil in both cases.
func (c *Catalog) Get(cat Category) []*Control {
	if c == nil {
		return nil
	}
	return c.Controls[cat]
}

// TracksOf returns the tracks associated with the given predicate-type
// URI in this catalog. The empty slice means no loaded control references
// the predicate type. A slice of length > 1 means the predicate type is
// declared under multiple tracks; callers must use ForceTrack (or the
// CLI's --track flag) to disambiguate.
func (c *Catalog) TracksOf(predicateType string) []Track {
	if c == nil {
		return nil
	}
	return c.PredicateTracks[predicateType]
}

// BuildPredicateTracks is the exported wrapper used by tests to build a
// PredicateTracks map from a flat slice of controls. Production code
// uses the loader, which calls the same logic internally.
func BuildPredicateTracks(ctrls []*Control) map[string][]Track {
	return buildPredicateTracks(ctrls)
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
		PredicateTracks: map[string][]Track{},
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

	cat.PredicateTracks = buildPredicateTracks(flatten(cat.Controls))
	return cat, nil
}

// flatten returns every control across every category as a single slice.
func flatten(byCategory map[Category][]*Control) []*Control {
	out := make([]*Control, 0)
	for _, group := range byCategory {
		out = append(out, group...)
	}
	return out
}

// buildPredicateTracks walks ctrls and returns the predicate-type →
// tracks map. Same predicate appearing under more than one track is
// allowed — disambiguation happens later via VerificationOptions.ForceTrack.
// Used both for the embedded catalog assembly and (in tests) for
// user-supplied control sets.
func buildPredicateTracks(ctrls []*Control) map[string][]Track {
	out := map[string][]Track{}
	for _, ctrl := range ctrls {
		track := Track(ctrl.Track)
		for _, ck := range ctrl.Checks {
			tracks := out[ck.PredicateType]
			already := false
			for _, t := range tracks {
				if t == track {
					already = true
					break
				}
			}
			if !already {
				out[ck.PredicateType] = append(tracks, track)
			}
		}
	}
	return out
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
