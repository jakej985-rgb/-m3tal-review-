package statemachine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/semantic/golang"
	"gopkg.in/yaml.v3"
)

// fixtureExpect is the expect.yaml format for statemachine fixtures:
// field-level assertions (never full snapshots) like the review
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
	// Covered optionally lists states that must appear in the
	// contract's StatesCovered.
	Covered []string `yaml:"covered"`
	// Truncated asserts the result's truncation flag.
	Truncated *bool `yaml:"truncated"`
}

// TestFixtureSuite runs every case under testdata/: each directory is
// a self-contained Go module plus contract.yaml and expect.yaml.
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
	contractData, err := os.ReadFile(filepath.Join(dir, "contract.yaml"))
	if err != nil {
		t.Fatalf("read contract.yaml: %v", err)
	}
	contract, err := ParseContract(contractData)
	if err != nil {
		t.Fatalf("ParseContract: %v", err)
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

	// Covered states.
	for _, state := range expect.Covered {
		found := false
		for _, cr := range res.Contracts {
			for _, s := range cr.StatesCovered {
				if s == state {
					found = true
				}
			}
		}
		if !found {
			t.Fatalf("state %q not covered; contracts: %+v", state, res.Contracts)
		}
	}

	if expect.Truncated != nil && res.Truncated != *expect.Truncated {
		t.Fatalf("truncated = %v, want %v", res.Truncated, *expect.Truncated)
	}
}

// TestBudgetTruncation verifies that exhausted budgets are reported
// through Result.Budgets, diagnostics, and the Truncated flag — and
// that no finding can be proven when analysis was incomplete.
func TestBudgetTruncation(t *testing.T) {
	dir := filepath.Join("testdata", "consume-twice")
	prog, err := golang.Load(context.Background(), golang.Options{Dir: dir, Pattern: "./..."})
	if err != nil {
		t.Fatalf("golang.Load: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "contract.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	contract, err := ParseContract(data)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Evaluate(context.Background(), prog, []*Contract{contract}, Options{MaxSteps: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Fatal("expected truncated result with MaxSteps=3")
	}
	var sawBudget, sawDiag bool
	for _, b := range res.Budgets {
		if b.Name == "max-steps" && b.Truncated {
			sawBudget = true
		}
	}
	for _, d := range res.Diagnostics {
		if strings.Contains(d.Message, "max-steps") {
			sawDiag = true
		}
	}
	if !sawBudget || !sawDiag {
		t.Fatalf("missing budget/diagnostic reporting: budgets=%v diags=%v", res.Budgets, res.Diagnostics)
	}
	for _, f := range res.Findings {
		if f.Status == "proven" {
			t.Fatalf("finding cannot be proven under truncation: %+v", f)
		}
	}
}

// TestAmbiguousBindingReported verifies ambiguous function bindings
// are diagnostics, never guesses (covered by the ambiguous fixture,
// asserted here at the Bind level too).
func TestAmbiguousBindingReported(t *testing.T) {
	dir := filepath.Join("testdata", "ambiguous")
	prog, err := golang.Load(context.Background(), golang.Options{Dir: dir, Pattern: "./..."})
	if err != nil {
		t.Fatalf("golang.Load: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "contract.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	contract, err := ParseContract(data)
	if err != nil {
		t.Fatal(err)
	}
	bc := Bind(prog, contract)
	if len(bc.EventFuncs) != 0 {
		t.Fatalf("ambiguous binding should not resolve any functions: %v", bc.EventFuncs)
	}
	var sawAmbig bool
	for _, d := range bc.Diagnostics {
		if strings.Contains(d.Message, "ambiguous") {
			sawAmbig = true
		}
	}
	if !sawAmbig {
		t.Fatalf("expected ambiguous diagnostic; got %v", bc.Diagnostics)
	}
}
