package flow

import (
	"context"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
)

const attackPathFixture = `package main

import (
	"os"
	"path/filepath"
)

func DirectHandler(p string) {
	os.Open(p)
}

func CleanedHandler(p string) {
	safe := filepath.Clean(p)
	os.Open(safe)
}

func stepB(target string) {
	os.RemoveAll(target)
}

func stepA(val string) {
	stepB(val)
}

func InterprocEntry(input string) {
	stepA(input)
}

func ShallowEntry(query string) {
	os.Open(query)
}

func main() {}
`

func loadAttackPathAnalyzer(t *testing.T) *Analyzer {
	t.Helper()
	files := map[string]string{
		"go.mod":  "module testmod\n\ngo 1.22\n",
		"main.go": attackPathFixture,
	}
	prog := loadProgram(t, files)
	a := NewAnalyzer(prog, Options{})
	a.Analyze(context.Background())
	return a
}

func checkDirectConfirmedPath(t *testing.T, analyzer *Analyzer) {
	paths, findings, err := FindAttackPaths(
		context.Background(), analyzer, AttackPathOptions{},
	)
	if err != nil || len(paths) == 0 || len(findings) == 0 {
		t.Fatalf("unexpected paths/findings: err=%v, len(p)=%d", err, len(paths))
	}

	foundDirect := false
	for _, p := range paths {
		if strings.Contains(p.Source.Detail, "DirectHandler") && p.Status == PathConfirmed {
			foundDirect = true
			if len(p.Steps) < 2 {
				t.Errorf("expected >= 2 steps, got %d", len(p.Steps))
			}
		}
	}
	if !foundDirect {
		t.Errorf("DirectHandler path not confirmed")
	}

	f := findings[0]
	if f.Trace != analysis.TraceSourceToSink {
		t.Errorf("trace want source-to-sink, got %s", f.Trace)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("finding validation error: %v", err)
	}
}

func checkSanitizedBlockedPath(t *testing.T, analyzer *Analyzer) {
	opts := AttackPathOptions{IncludeBlocked: true}
	paths, _, _ := FindAttackPaths(context.Background(), analyzer, opts)
	foundBlocked := false
	for _, p := range paths {
		if strings.Contains(p.Source.Detail, "CleanedHandler") && p.Status == PathBlocked {
			foundBlocked = true
			if len(p.Sanitizers) == 0 {
				t.Errorf("expected sanitizers on blocked path")
			}
		}
	}
	if !foundBlocked {
		t.Errorf("CleanedHandler path was not blocked")
	}
}

func checkInterprocPath(t *testing.T, analyzer *Analyzer) {
	paths, _, _ := FindAttackPaths(
		context.Background(), analyzer, AttackPathOptions{},
	)
	foundInter := false
	for _, p := range paths {
		if strings.Contains(p.Source.Detail, "InterprocEntry") && p.Status == PathConfirmed {
			foundInter = true
			if len(p.Steps) < 3 {
				t.Errorf("expected >= 3 steps across calls, got %d", len(p.Steps))
			}
		}
	}
	if !foundInter {
		t.Errorf("InterprocEntry path not confirmed")
	}
}

func checkDepthTruncation(t *testing.T, analyzer *Analyzer) {
	opts := AttackPathOptions{MaxDepth: 1}
	paths, _, _ := FindAttackPaths(context.Background(), analyzer, opts)
	if len(paths) == 0 {
		t.Fatal("expected truncated paths")
	}
	if paths[0].Status != PathIncomplete {
		t.Errorf("want PathIncomplete, got %s", paths[0].Status)
	}
}

func TestAttackPathSuite(t *testing.T) {
	analyzer := loadAttackPathAnalyzer(t)

	t.Run("confirmed direct path", func(t *testing.T) {
		checkDirectConfirmedPath(t, analyzer)
	})
	t.Run("sanitized path blocked", func(t *testing.T) {
		checkSanitizedBlockedPath(t, analyzer)
	})
	t.Run("interprocedural call path", func(t *testing.T) {
		checkInterprocPath(t, analyzer)
	})
	t.Run("budget depth truncation", func(t *testing.T) {
		checkDepthTruncation(t, analyzer)
	})
}
