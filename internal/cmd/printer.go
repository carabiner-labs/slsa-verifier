// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"

	"github.com/carabiner-labs/slsa-verifier/pkg/slsa"
)

// printResult writes the full verification roster: a top-line PASS/FAIL +
// SLSA level, then a per-layer (Core / BuildType / User) list of every
// applicable control with its status. Skipped controls are hidden unless
// verbose is true. fatih/color is used for ✓/✗ glyphs when stdout is a
// TTY; otherwise plain bracketed status tags are emitted.
func printResult(w io.Writer, result *slsa.Result, verbose bool) {
	if result.Pass() {
		writef(w, "%s\n", greenf("PASS"))
	} else {
		writef(w, "%s\n", redf("FAIL"))
	}
	if result.SLSALevel > 0 {
		if result.SpecVersion != "" {
			writef(w, "SLSA Level: %d (spec v%s)\n", result.SLSALevel, result.SpecVersion)
		} else {
			writef(w, "SLSA Level: %d\n", result.SLSALevel)
		}
	}
	if result.Message != "" {
		writef(w, "%s\n", result.Message)
	}
	writef(w, "\n")

	printLayer(w, "Core", result.CoreResults, verbose)
	// A nil buildType slice means the layer was not evaluated at all
	// (e.g. the source track, which has no buildType concept): omit the
	// section instead of printing an empty roster.
	if result.BuildTypeResults != nil {
		printLayer(w, "BuildType", result.BuildTypeResults, verbose)
	}
	printLayer(w, "User", result.UserResults, verbose)
}

// printLayer renders one layer's roster as an aligned table. Within a
// layer the entries are ordered by SLSA level ascending, then by id:
// L1 controls before L2 before L3, alphabetical inside a level. Results
// without a level (level 0) sort first so they don't break the chain.
func printLayer(w io.Writer, label string, results []*slsa.ControlResult, verbose bool) {
	visible := filterVisible(results, verbose)
	sort.SliceStable(visible, func(i, j int) bool {
		if visible[i].SLSALevel != visible[j].SLSALevel {
			return visible[i].SLSALevel < visible[j].SLSALevel
		}
		return visible[i].ID < visible[j].ID
	})

	writef(w, "%s controls:\n", label)
	if len(visible) == 0 {
		if len(results) == 0 {
			writef(w, "  (none)\n\n")
		} else {
			// All present results were filtered out (skipped + non-verbose).
			writef(w, "  (no applicable controls)\n\n")
		}
		return
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, cr := range visible {
		marker := statusMarker(cr.Status)
		level := ""
		if cr.SLSALevel > 0 {
			level = fmt.Sprintf("L%d", cr.SLSALevel)
		}
		line := fmt.Sprintf("  %s\t%s\t%s", marker, level, cr.ID)
		if verbose && cr.Title != "" {
			line += "\t" + cr.Title
		}
		if (cr.Status == slsa.StatusFail || cr.Status == slsa.StatusError) && cr.Message != "" {
			line += "\t" + dimf(cr.Message)
		}
		writef(tw, "%s\n", line)
	}
	flushTabWriter(tw)
	writef(w, "\n")
}

func flushTabWriter(tw *tabwriter.Writer) {
	tw.Flush() //nolint:errcheck,gosec
}

// filterVisible drops StatusSkipped entries when verbose is false.
func filterVisible(results []*slsa.ControlResult, verbose bool) []*slsa.ControlResult {
	if verbose {
		return results
	}
	out := make([]*slsa.ControlResult, 0, len(results))
	for _, cr := range results {
		if cr.Status == slsa.StatusSkipped {
			continue
		}
		out = append(out, cr)
	}
	return out
}

// statusMarker returns the per-status marker. On a TTY renders with color
func statusMarker(s slsa.Status) string {
	if color.NoColor {
		return "[" + string(s) + "]"
	}
	switch s {
	case slsa.StatusPass:
		return color.GreenString("✓")
	case slsa.StatusFail:
		return color.RedString("✗")
	case slsa.StatusError:
		return color.YellowString("!")
	case slsa.StatusSkipped:
		return color.New(color.FgHiBlack).Sprint("·")
	default:
		return "?"
	}
}

func greenf(s string) string {
	if color.NoColor {
		return s
	}
	return color.GreenString(s)
}

func redf(s string) string {
	if color.NoColor {
		return s
	}
	return color.RedString(s)
}

func dimf(s string) string {
	s = strings.TrimSpace(s)
	if color.NoColor {
		return s
	}
	return color.New(color.FgHiBlack).Sprint(s)
}
