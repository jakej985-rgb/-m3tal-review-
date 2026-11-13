package typestate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
	"github.com/jakej985-rgb/m3tal-review/internal/analysis/statemachine"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic/golang"
	"gopkg.in/yaml.v3"
)

// fixtureExpect is the expect.yaml format for typestate fixtures:
// field-level assertions (never full snapshots), mirroring the
// statemachine fixture harness.
type fixtureExpect struct {
	// Findings lists expected findings; the count must match exactly.
	Findings []struct {
		Rule            string `yaml:"rule"`
		MessageContains string `yaml:"message_contains"`
		// Status optionally asserts the finding's epistemic status
		// ("proven" or "potential").
		Status string `yaml:"status"`
	} `yaml:"findings"`
	// Diagnostics lists substrings that must each appear in at least
	// one diagnostic.
	Diagnostics []struct {
		MessageContains string `yaml:"message_contains"`
	} `yaml:"diagnostics"`
	// Covered optionally lists states that must appear in some
	// contract's StatesCovered.
	Covered []string `yaml:"covered"`
}

// TestFixtureSuite runs every case under testdata/: each directory is
// a self-contained Go module plus typestate.yaml and expect.yaml.
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
	specData, err := os.ReadFile(filepath.Join(dir, "typestate.yaml"))
	if err != nil {
		t.Fatalf("read typestate.yaml: %v", err)
	}
	spec, err := ParseSpec(specData)
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	expectData, err := os.ReadFile(filepath.Join(dir, "expect.yaml"))
	if err != nil {
		t.Fatalf("read expect.yaml: %v", err)
	}
	var expect fixtureExpect
	if err := yaml.Unmarshal(expectData, &expect); err != nil {
		t.Fatalf("parse expect.yaml: %v", err)
	}

	res, err := Analyze(context.Background(), prog, []*Spec{spec}, statemachine.Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
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
			if want.Status != "" && string(f.Status) != want.Status {
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
}

// TestParseSpec covers schema validation and defaults.
func TestParseSpec(t *testing.T) {
	good := `
schema_version: typestate/1
id: c1
operations:
  - kind: consume
    function: {name: Consume}
`
	s, err := ParseSpec([]byte(good))
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	if s.ID != "c1" || len(s.Operations) != 1 {
		t.Fatalf("unexpected spec: %+v", s)
	}
	if diags := s.Check(); len(diags) != 0 {
		t.Fatalf("unexpected check diagnostics: %v", diags)
	}

	bad := `
schema_version: typestate/99
id: c1
`
	if _, err := ParseSpec([]byte(bad)); err == nil {
		t.Fatal("expected schema_version error")
	}
}

// TestCheckValidation covers spec validation diagnostics.
func TestCheckValidation(t *testing.T) {
	s := &Spec{
		SchemaVersion: SchemaVersion,
		ID:            "bad",
		Operations: []OperationSpec{
			{Kind: "teleport"},
			{Kind: KindConsume}, // missing function
			{Name: "dup", Kind: KindUse, Function: &statemachine.FunctionSpec{Name: "A"}},
			{Name: "dup", Kind: KindUse, Function: &statemachine.FunctionSpec{Name: "B"}},
		},
	}
	diags := s.Check()
	var sawKind, sawFunc, sawDup bool
	for _, d := range diags {
		if strings.Contains(d.Message, "unknown kind") {
			sawKind = true
		}
		if strings.Contains(d.Message, "function binding is required") {
			sawFunc = true
		}
		if strings.Contains(d.Message, "collides") || strings.Contains(d.Message, "duplicate") {
			sawDup = true
		}
	}
	if !sawKind || !sawFunc || !sawDup {
		t.Fatalf("missing expected diagnostics: %v", diags)
	}
}

// TestBuildContract verifies the derived contract structure.
func TestBuildContract(t *testing.T) {
	s := &Spec{
		SchemaVersion: SchemaVersion,
		ID:            "lc",
		Operations: []OperationSpec{
			{Kind: KindConsume, Function: &statemachine.FunctionSpec{Name: "Consume"}},
			{Kind: KindUse, Function: &statemachine.FunctionSpec{Name: "Check"}},
			{Kind: KindReset, Function: &statemachine.FunctionSpec{Name: "Reset"}},
		},
	}
	c := BuildContract(s)
	if c == nil {
		t.Fatal("BuildContract returned nil")
	}
	if len(c.States) != 2 || c.States[0].Name != stateAvailable || !c.States[0].Initial || c.States[1].Name != stateConsumed {
		t.Fatalf("unexpected states: %+v", c.States)
	}
	if len(c.Events) != 3 || len(c.Transitions) != 3 {
		t.Fatalf("unexpected events/transitions: %d/%d", len(c.Events), len(c.Transitions))
	}
	// consume: available -> consumed; use: available -> available;
	// reset: consumed -> available.
	want := map[string][2]string{
		"consume": {stateAvailable, stateConsumed},
		"use":     {stateAvailable, ""},
		"reset":   {stateConsumed, stateAvailable},
	}
	for _, tr := range c.Transitions {
		w, ok := want[tr.Event]
		if !ok {
			t.Fatalf("unexpected transition event %q", tr.Event)
		}
		from, _ := tr.From.(string)
		if from != w[0] || tr.To != w[1] {
			t.Fatalf("transition %q: from=%v to=%q, want from=%q to=%q", tr.Event, tr.From, tr.To, w[0], w[1])
		}
	}
}

// TestRuleIDs verifies kind → rule ID mapping.
func TestRuleIDs(t *testing.T) {
	cases := map[string]string{
		KindConsume: "typestate-double-consume",
		KindUse:     "typestate-use-after-consume",
		KindReset:   "typestate-invalid-reset",
		"other":     "typestate-illegal-transition",
	}
	for kind, want := range cases {
		if got := ruleIDForKind(kind); got != want {
			t.Fatalf("ruleIDForKind(%q) = %q, want %q", kind, got, want)
		}
	}
}

// TestFindingEvidence verifies that a violation finding carries a
// state-transition evidence trace from availability through the
// invalid use.
func TestFindingEvidence(t *testing.T) {
	dir := filepath.Join("testdata", "dual-auth")
	prog, err := golang.Load(context.Background(), golang.Options{Dir: dir, Pattern: "./..."})
	if err != nil {
		t.Fatalf("golang.Load: %v", err)
	}
	specData, err := os.ReadFile(filepath.Join(dir, "typestate.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := ParseSpec(specData)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Analyze(context.Background(), prog, []*Spec{spec}, statemachine.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.Trace != analysis.TraceStateTransition {
		t.Fatalf("trace = %q, want state-transition", f.Trace)
	}
	if f.Analyzer != "typestate" {
		t.Fatalf("analyzer = %q, want typestate", f.Analyzer)
	}
	// Evidence must show the lifecycle: availability → consumed →
	// rejected second consume.
	var sawFreshToConsumed, sawRejected bool
	for _, ev := range f.Evidence {
		if ev.Kind == analysis.EvidenceState {
			if strings.Contains(ev.Note, "available") && strings.Contains(ev.Note, "consumed") {
				sawFreshToConsumed = true
			}
			if strings.HasPrefix(ev.Note, "rejected:") {
				sawRejected = true
			}
		}
	}
	if !sawFreshToConsumed || !sawRejected {
		t.Fatalf("evidence lacks lifecycle trace: %+v", f.Evidence)
	}
}
