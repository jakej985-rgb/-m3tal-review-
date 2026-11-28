package rust

import (
	_ "embed"
	"encoding/json"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/apps/rust/bug"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/rust/security"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/rust/slop"
	"github.com/jakej985-rgb/m3tal-review/protocol"
)

//go:embed review-app.json
var embeddedManifest []byte

type manifest struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Extensions []string `json:"extensions"`
	Inputs     []string `json:"inputs"`
}

func loadManifest() manifest {
	var m manifest
	_ = json.Unmarshal(embeddedManifest, &m)
	return m
}

var catalog = func() []protocol.RuleInfo {
	var all []protocol.RuleInfo
	all = append(all, bug.Rules()...)
	all = append(all, security.Rules()...)
	all = append(all, slop.Rules()...)
	return all
}()

// App implements the Go-based Rust review app.
type App struct{}

// Describe returns the review-app/1 capability description for review-rust.
func (App) Describe() protocol.DescribeResult {
	m := loadManifest()
	return protocol.DescribeResult{
		Protocol:   protocol.Version,
		Kind:       protocol.Kind,
		App:        protocol.AppInfo{Name: m.Name, Version: m.Version},
		Extensions: m.Extensions,
		Inputs:     m.Inputs,
		Rules:      catalog,
	}
}

// Run analyzes Rust files using the bug, security, and slop submodules.
func (App) Run(in protocol.Input) protocol.Output {
	start := time.Now()
	m := loadManifest()
	var findings []protocol.Finding
	var unanalyzed []protocol.UnanalyzedFile

	for _, f := range in.Files {
		if f.Status == "deleted" {
			unanalyzed = append(unanalyzed, protocol.UnanalyzedFile{File: f.Path, Reason: "deleted"})
			continue
		}
		if strings.TrimSpace(f.Content) == "" {
			continue
		}
		addedSet := makeLineSet(f.AddedLines)
		allowed := func(line int) bool {
			return addedSet == nil || addedSet[line]
		}
		lines := strings.Split(f.Content, "\n")
		isTest := strings.HasSuffix(f.Path, "_test.rs") || strings.HasPrefix(f.Path, "tests/")
		findings = append(findings, bug.Analyze(f.Path, lines, allowed, isTest)...)
		findings = append(findings, security.Analyze(f.Path, lines, allowed, isTest)...)
		findings = append(findings, slop.Analyze(f.Path, lines, allowed)...)
	}

	return protocol.Output{
		Protocol:   protocol.Version,
		App:        protocol.AppInfo{Name: m.Name, Version: m.Version},
		Findings:   findings,
		Unanalyzed: unanalyzed,
		Stats: protocol.Stats{
			Files:      len(in.Files),
			Rules:      len(catalog),
			DurationMs: time.Since(start).Milliseconds(),
		},
	}
}

func makeLineSet(lines []int) map[int]bool {
	if len(lines) == 0 {
		return nil
	}
	s := make(map[int]bool, len(lines))
	for _, l := range lines {
		s[l] = true
	}
	return s
}
