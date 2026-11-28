package golang

import (
	_ "embed"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/apps/golang/bug"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/golang/security"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/golang/slop"
	"github.com/jakej985-rgb/m3tal-review/protocol"
)

//go:embed review-app.json
var embeddedManifest []byte

type manifest struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Protocol   string   `json:"protocol"`
	Extensions []string `json:"extensions"`
	Inputs     []string `json:"inputs"`
	Rules      []string `json:"rules"`
}

func loadManifest() manifest {
	var m manifest
	_ = json.Unmarshal(embeddedManifest, &m)
	return m
}

// AppVersion returns the embedded version of review-go.
func AppVersion() string {
	return loadManifest().Version
}

var catalog = func() []protocol.RuleInfo {
	var all []protocol.RuleInfo
	all = append(all, bug.Rules()...)
	all = append(all, security.Rules()...)
	all = append(all, slop.Rules()...)
	return all
}()

// Describe returns the protocol DescribeResult for review-go.
func Describe() protocol.DescribeResult {
	m := loadManifest()
	return protocol.DescribeResult{
		Protocol:     protocol.Version,
		Kind:         protocol.Kind,
		App:          protocol.AppInfo{Name: m.Name, Version: m.Version},
		Extensions:   m.Extensions,
		Inputs:       m.Inputs,
		Capabilities: []string{protocol.CapabilityFix},
		Rules:        catalog,
		ConfigSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"min_severity": map[string]any{"type": "string"},
			},
		},
	}
}

// Run analyzes the input files using the bug, security, and slop submodules.
func Run(in protocol.Input) protocol.Output {
	start := time.Now()
	m := loadManifest()
	var findings []protocol.Finding
	var unanalyzed []protocol.UnanalyzedFile

	fset := token.NewFileSet()
	for _, f := range in.Files {
		if f.Status == "deleted" {
			unanalyzed = append(unanalyzed, protocol.UnanalyzedFile{
				File:   f.Path,
				Reason: "deleted",
			})
			continue
		}
		if strings.TrimSpace(f.Content) == "" {
			continue
		}
		parsed, err := parser.ParseFile(fset, f.Path, f.Content, parser.ParseComments)
		if err != nil {
			unanalyzed = append(unanalyzed, protocol.UnanalyzedFile{
				File:   f.Path,
				Reason: "parse error: " + err.Error(),
			})
			continue
		}
		if ast.IsGenerated(parsed) {
			continue
		}
		addedSet := makeLineSet(f.AddedLines)
		lines := strings.Split(f.Content, "\n")
		getLine := func(line int) string {
			if line >= 1 && line <= len(lines) {
				return strings.TrimSpace(lines[line-1])
			}
			return ""
		}
		allowed := func(line int) bool {
			return lineAllowed(line, addedSet)
		}
		isTestFile := strings.HasSuffix(f.Path, "_test.go")

		findings = append(findings, bug.Analyze(fset, parsed, f.Path, getLine, allowed, isTestFile)...)
		findings = append(findings, security.Analyze(fset, parsed, f.Path, getLine, allowed, isTestFile)...)
		findings = append(findings, slop.Analyze(fset, parsed, f.Path, getLine, allowed)...)
	}

	var diags []protocol.Diagnostic
	if vetOn, _ := in.Config["vet"].(bool); vetOn || in.Run.Mode == "audit" {
		vetFindings, vetDiags := bug.RunVet(in.Run.Root, in.Files)
		findings = append(findings, vetFindings...)
		diags = append(diags, vetDiags...)
	}

	if minSev, ok := in.Config["min_severity"].(string); ok && protocol.IsValidSeverity(minSev) {
		findings = filterMinSeverity(findings, minSev)
	}

	return protocol.Output{
		Protocol:    protocol.Version,
		App:         protocol.AppInfo{Name: m.Name, Version: m.Version},
		Findings:    findings,
		Diagnostics: diags,
		Unanalyzed:  unanalyzed,
		Stats: protocol.Stats{
			Files:      len(in.Files),
			Rules:      len(catalog),
			DurationMs: time.Since(start).Milliseconds(),
		},
	}
}

func severityRank(s string) int {
	switch s {
	case protocol.SeverityCritical:
		return 4
	case protocol.SeverityHigh:
		return 3
	case protocol.SeverityMedium:
		return 2
	case protocol.SeverityLow:
		return 1
	default:
		return 0
	}
}

func filterMinSeverity(findings []protocol.Finding, minSev string) []protocol.Finding {
	minRank := severityRank(minSev)
	var out []protocol.Finding
	for _, f := range findings {
		if severityRank(f.Severity) >= minRank {
			out = append(out, f)
		}
	}
	return out
}

func makeLineSet(lines []int) map[int]struct{} {
	if len(lines) == 0 {
		return nil
	}
	s := make(map[int]struct{}, len(lines))
	for _, l := range lines {
		s[l] = struct{}{}
	}
	return s
}

func lineAllowed(line int, added map[int]struct{}) bool {
	if added == nil {
		return true
	}
	_, ok := added[line]
	return ok
}
