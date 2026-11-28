package protocol

import (
	"fmt"
	"strings"
)

// CapabilityFix declares that an app supports the `fix` remediation verb.
const CapabilityFix = "fix"

// FixInput is the stdin JSON request sent to `<app> --fix`.
type FixInput struct {
	Protocol string         `json:"protocol"`
	Run      RunInfo        `json:"run"`
	Config   map[string]any `json:"config,omitempty"`
	Findings []Finding      `json:"findings"`
	Files    []File         `json:"files"`
}

// Patch represents a single deterministic source replacement produced by an app.
type Patch struct {
	Rule        string `json:"rule"`
	File        string `json:"file"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	Replacement string `json:"replacement"`
	Summary     string `json:"summary"`
}

// FixOutput is the stdout JSON response returned by `<app> --fix`.
type FixOutput struct {
	Protocol    string       `json:"protocol"`
	App         AppInfo      `json:"app"`
	Patches     []Patch      `json:"patches"`
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
}

// ValidateFixOutput checks all invariants of a FixOutput response.
func ValidateFixOutput(out FixOutput, expectedApp string, sentFiles map[string]struct{}) error {
	if out.Protocol != Version {
		return fail("$.protocol", fmt.Sprintf("expected %q, got %q", Version, out.Protocol))
	}
	if expectedApp != "" && out.App.Name != expectedApp {
		return fail("$.app.name", fmt.Sprintf("expected %q, got %q", expectedApp, out.App.Name))
	}
	for i, p := range out.Patches {
		prefix := fmt.Sprintf("$.patches[%d]", i)
		if !IsValidRuleID(p.Rule) {
			return fail(prefix+".rule", fmt.Sprintf("invalid rule id %q", p.Rule))
		}
		if err := ValidateRelativePath(p.File); err != nil {
			return fail(prefix+".file", err.Error())
		}
		if sentFiles != nil {
			if _, ok := sentFiles[p.File]; !ok {
				return fail(prefix+".file", fmt.Sprintf("file %q was not in request", p.File))
			}
		}
		if p.StartLine < 1 || p.EndLine < p.StartLine {
			return fail(prefix+".start_line", "invalid line range")
		}
		if strings.TrimSpace(p.Summary) == "" {
			return fail(prefix+".summary", "summary must be non-empty")
		}
	}
	return nil
}
