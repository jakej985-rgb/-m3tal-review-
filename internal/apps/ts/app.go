package ts

import (
	_ "embed"
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/apps/ts/bug"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/ts/security"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/ts/slop"
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

// App implements the Go-based TypeScript/JavaScript review app.
type App struct{}

// Describe returns the review-app/1 capability description for review-ts.
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

// Run analyzes TS/JS files using the bug, security, and slop submodules.
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
		rawLines := strings.Split(f.Content, "\n")
		maskedLines := strings.Split(maskCommentsAndStrings(f.Content), "\n")
		ext := strings.ToLower(filepath.Ext(f.Path))
		isTS := ext == ".ts" || ext == ".tsx" || ext == ".mts" || ext == ".cts"

		findings = append(findings, bug.Analyze(f.Path, maskedLines, rawLines, allowed)...)
		findings = append(findings, security.Analyze(f.Path, f.Content, maskedLines, rawLines, allowed)...)
		findings = append(findings, slop.Analyze(f.Path, isTS, maskedLines, rawLines, allowed)...)
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

func maskCommentsAndStrings(src string) string {
	var out strings.Builder
	out.Grow(len(src))
	maskTSRange(src, 0, false, &out)
	return out.String()
}

func maskTSRange(src string, i int, stopAtCloseBrace bool, out *strings.Builder) int {
	n := len(src)
	braceDepth := 0
	for i < n {
		ch := src[i]
		var next byte
		if i+1 < n {
			next = src[i+1]
		}
		if stopAtCloseBrace {
			if ch == '{' {
				braceDepth++
			} else if ch == '}' {
				if braceDepth == 0 {
					out.WriteByte('}')
					return i + 1
				}
				braceDepth--
			}
		}
		if ch == '/' && next == '/' {
			for i < n && src[i] != '\n' {
				out.WriteByte(' ')
				i++
			}
			continue
		}
		if ch == '/' && next == '*' {
			out.WriteString("  ")
			i += 2
			for i < n && !(src[i] == '*' && i+1 < n && src[i+1] == '/') {
				if src[i] == '\n' {
					out.WriteByte('\n')
				} else {
					out.WriteByte(' ')
				}
				i++
			}
			if i < n {
				out.WriteString("  ")
				i += 2
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			q := ch
			out.WriteByte(q)
			i++
			for i < n && src[i] != q {
				if src[i] == '\\' && i+1 < n {
					out.WriteByte(' ')
					if src[i+1] == '\n' {
						out.WriteByte('\n')
					} else {
						out.WriteByte(' ')
					}
					i += 2
					continue
				}
				if src[i] == '\n' {
					out.WriteByte('\n')
				} else {
					out.WriteByte(' ')
				}
				i++
			}
			if i < n {
				out.WriteByte(q)
				i++
			}
			continue
		}
		if ch == '`' {
			out.WriteByte('`')
			i++
			for i < n && src[i] != '`' {
				if src[i] == '\\' && i+1 < n {
					out.WriteByte(' ')
					if src[i+1] == '\n' {
						out.WriteByte('\n')
					} else {
						out.WriteByte(' ')
					}
					i += 2
					continue
				}
				if src[i] == '$' && i+1 < n && src[i+1] == '{' {
					out.WriteString("${")
					i = maskTSRange(src, i+2, true, out)
					continue
				}
				if src[i] == '\n' {
					out.WriteByte('\n')
				} else {
					out.WriteByte(' ')
				}
				i++
			}
			if i < n {
				out.WriteByte('`')
				i++
			}
			continue
		}
		out.WriteByte(ch)
		i++
	}
	return i
}
