// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package controls

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadEmbedded(t *testing.T) {
	t.Parallel()

	cat, err := LoadEmbedded()
	require.NoError(t, err)
	require.NotNil(t, cat)

	buildCore := cat.Get(BuildCore)
	require.NotEmpty(t, buildCore, "build/core should contain at least one control")

	var found *Control
	for _, c := range buildCore {
		if c.ID == "source-repo-match" {
			found = c
			break
		}
	}
	require.NotNil(t, found, "expected to find source-repo-match control")
	assert.Equal(t, "Source Repository Matches Expected URI", found.Title)
	require.Len(t, found.Checks, 1)
	assert.Equal(t, "https://slsa.dev/provenance/v1", found.Checks[0].PredicateType)
	assert.Contains(t, found.Checks[0].Parameters, "expected_source")
}

func TestLoadEmbeddedSourceCore(t *testing.T) {
	t.Parallel()

	cat, err := LoadEmbedded()
	require.NoError(t, err)
	require.NotEmpty(t, cat.Get(SourceCore), "source/core should contain at least one control")
}

func TestParseYAMLMultiDoc(t *testing.T) {
	t.Parallel()

	src := []byte(`id: a
title: A
checks:
  - predicateType: https://slsa.dev/provenance/v1
    expression: "true"
---
id: b
title: B
checks:
  - predicateType: https://slsa.dev/provenance/v1
    expression: "false"
`)

	out, err := parseYAML(src)
	require.NoError(t, err)
	require.Len(t, out, 2)
	assert.Equal(t, "a", out[0].ID)
	assert.Equal(t, "b", out[1].ID)
}

func TestParseYAMLSingleDoc(t *testing.T) {
	t.Parallel()

	src := []byte(`id: only
title: Only
checks:
  - predicateType: https://slsa.dev/provenance/v1
    expression: "true"
`)

	out, err := parseYAML(src)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "only", out[0].ID)
}

func TestParseYAMLSkipsEmptyDocs(t *testing.T) {
	t.Parallel()

	src := []byte(`---
id: only
title: Only
checks:
  - predicateType: https://slsa.dev/provenance/v1
    expression: "true"
---
`)

	out, err := parseYAML(src)
	require.NoError(t, err)
	require.Len(t, out, 1)
}

func TestControlValidate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		ctrl    Control
		wantErr bool
	}{
		{
			name: "valid",
			ctrl: Control{
				ID:    "x",
				Title: "X",
				Checks: []Check{{
					PredicateType: "t",
					Expression:    "true",
				}},
			},
			wantErr: false,
		},
		{
			name: "missing id",
			ctrl: Control{
				Title: "X",
				Checks: []Check{{
					PredicateType: "t",
					Expression:    "true",
				}},
			},
			wantErr: true,
		},
		{
			name: "missing title",
			ctrl: Control{
				ID: "x",
				Checks: []Check{{
					PredicateType: "t",
					Expression:    "true",
				}},
			},
			wantErr: true,
		},
		{
			name:    "no checks",
			ctrl:    Control{ID: "x", Title: "X"},
			wantErr: true,
		},
		{
			name: "check missing expression",
			ctrl: Control{
				ID:    "x",
				Title: "X",
				Checks: []Check{{
					PredicateType: "t",
				}},
			},
			wantErr: true,
		},
		{
			name: "check missing predicate type",
			ctrl: Control{
				ID:    "x",
				Title: "X",
				Checks: []Check{{
					Expression: "true",
				}},
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.ctrl.Validate()
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCategoryFromPath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		root, file string
		want       Category
	}{
		{"catalog", "catalog/build/core/foo.yaml", BuildCore},
		{"catalog", "catalog/source/core/bar.yaml", SourceCore},
		{"catalog", "catalog/build/buildType/x.yaml", BuildType},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, categoryFromPath(tc.root, tc.file))
	}
}
