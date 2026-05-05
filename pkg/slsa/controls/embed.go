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
type Catalog struct {
	Controls map[Category][]*Control
}

// Get returns the controls registered under the given category. Safe to call
// on a nil receiver and on missing categories — returns nil in both cases.
func (c *Catalog) Get(cat Category) []*Control {
	if c == nil {
		return nil
	}
	return c.Controls[cat]
}

// LoadEmbedded loads the controls compiled into the binary.
func LoadEmbedded() (*Catalog, error) {
	return loadFromFS(catalogFS, catalogRoot)
}

// loadFromFS walks the directory rooted at root in fsys and parses every
// YAML file found. Each file's location relative to root determines the
// category its controls are placed under.
func loadFromFS(fsys fs.FS, root string) (*Catalog, error) {
	cat := &Catalog{Controls: map[Category][]*Control{}}

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
		}
		cat.Controls[category] = append(cat.Controls[category], ctrls...)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return cat, nil
}

// categoryFromPath returns the directory of file relative to root, used as
// the Category key.
func categoryFromPath(root, file string) Category {
	rel := strings.TrimPrefix(file, root)
	rel = strings.TrimPrefix(rel, "/")
	return Category(path.Dir(rel))
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
