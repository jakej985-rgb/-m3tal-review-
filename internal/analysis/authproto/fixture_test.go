package authproto

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/semantic/golang"
	"gopkg.in/yaml.v3"
)

// fixtureExpect is the expect.yaml format for authproto fixtures:
// field-level assertions (never full snapshots) like the statemachine
// fixture harness.
type fixtureExpect struct {
	// Findings lists expected findings; the count must match exactly.
	Findings []struct {
		Rule            string `yaml:"rule"`
		MessageContains string `yaml:"message_contains"`
	} `yaml:"findings"`
	// Diagnostics lists substrings that must each appear in at least
	// one diagnostic.
	Diagnostics []struct {
		MessageContains string `yaml:"message_contains"`
	} `yaml:"diagnostics"`
	// Truncated asserts the result's truncation flag.
	Truncated *bool `yaml:"truncated"`
}

// TestFixtureSuite runs every case under testdata/: each directory is
// a self-contained Go module plus authproto.yaml and expect.yaml.
func TestFixtureSuite(t *testing.T) {
	root := filepath.Join("testdata")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		caseDir := filepath.Join(root, ent.Name())
		t.Run(ent.Name(), func(t *testing.T) { runFixture(t, caseDir) })
	}
}

func runFixture(t *testing.T, dir string) {
	t.Helper()
	prog, err := golang.Load(context.Background(), golang.Options{Dir: dir, Pattern: "./..."})
	if err != nil {
		t.Fatalf("golang.Load: %v", err)
	}
	contract, err := LoadContract(filepath.Join(dir, "authproto.yaml"))
	if err != nil {
		t.Fatalf("LoadContract: %v", err)
	}
	expectData, err := os.ReadFile(filepath.Join(dir, "expect.yaml"))
	if err != nil {
		t.Fatalf("read expect.yaml: %v", err)
	}
	var expect fixtureExpect
	if err := yaml.Unmarshal(expectData, &expect); err != nil {
		t.Fatalf("parse expect.yaml: %v", err)
	}

	res, err := Evaluate(context.Background(), prog, []*Contract{contract}, Options{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	// Findings: exact count, each expectation matches one finding.
	if len(res.Findings) != len(expect.Findings) {
		t.Fatalf("finding count = %d, want %d\nfindings: %v\ndiagnostics: %v",
			len(res.Findings), len(expect.Findings), res.Findings, res.Diagnostics)
	}
	used := make([]bool, len(res.Findings))
	for _, want := range expect.Findings {
		found := false
		for i, f := range res.Findings {
			if used[i] {
				continue
			}
			if want.Rule != "" && f.RuleID != want.Rule {
				continue
			}
			if want.MessageContains != "" && !strings.Contains(f.Message, want.MessageContains) {
				continue
			}
			used[i] = true
			found = true
			break
		}
		if !found {
			t.Fatalf("no finding matched %+v; findings: %v", want, res.Findings)
		}
	}

	// Diagnostics: each expectation must appear somewhere.
	for _, want := range expect.Diagnostics {
		found := false
		for _, d := range res.Diagnostics {
			if strings.Contains(d.Message, want.MessageContains) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("no diagnostic contains %q; diagnostics: %v", want.MessageContains, res.Diagnostics)
		}
	}

	if expect.Truncated != nil && res.Truncated != *expect.Truncated {
		t.Fatalf("truncated = %v, want %v", res.Truncated, *expect.Truncated)
	}
}
