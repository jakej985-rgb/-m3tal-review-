package pipeline

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
)

// e2eDir is a self-contained Go module with a typestate contract under
// .m3tal/contracts exercising the full pipeline: shared frontend load,
// contract discovery, multi-analyzer execution, and deterministic
// merge.
func e2eDir(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	return filepath.Join("testdata", "e2e")
}

func TestPipelineEndToEnd(t *testing.T) {
	dir := e2eDir(t)
	loader := NewLoader()
	opts := Options{
		Dir:         dir,
		Loader:      loader,
		MaxParallel: 4,
	}

	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.LoadError != "" {
		t.Fatalf("LoadError = %q", res.LoadError)
	}
	if res.Program == nil || res.Program.Packages == 0 {
		t.Fatal("expected a loaded program with packages")
	}
	if loader.Loads() != 1 {
		t.Fatalf("loader performed %d loads, want exactly 1 (shared frontend)", loader.Loads())
	}

	// typestate analyzer must have found the double-consume.
	var typestateResult *AnalyzerResult
	for i := range res.Analyzers {
		if res.Analyzers[i].Name == AnalyzerTypeState {
			typestateResult = &res.Analyzers[i]
		}
	}
	if typestateResult == nil {
		t.Fatal("typestate analyzer missing from results")
	}
	if typestateResult.Status != "completed" {
		t.Fatalf("typestate status = %q (%s)", typestateResult.Status, typestateResult.Message)
	}
	found := false
	for _, f := range res.Findings {
		if f.RuleID == "typestate-double-consume" {
			found = true
			if f.Analyzer != "typestate" {
				t.Fatalf("finding analyzer = %q, want typestate", f.Analyzer)
			}
			if f.Status != "proven" && f.Status != "potential" {
				t.Fatalf("finding status = %q", f.Status)
			}
		}
	}
	if !found {
		t.Fatal("expected a typestate-double-consume finding")
	}

	// Contract-free engines ran; contract-driven ones without inputs
	// skipped cleanly.
	statuses := map[string]string{}
	for _, a := range res.Analyzers {
		statuses[a.Name] = a.Status
	}
	for _, name := range []string{AnalyzerFlow, AnalyzerConcurrency} {
		if statuses[name] != "completed" {
			t.Fatalf("analyzer %s status = %q, want completed", name, statuses[name])
		}
	}
	for _, name := range []string{AnalyzerStateMachine, AnalyzerAuthProto, AnalyzerProtocol} {
		if statuses[name] != "skipped" {
			t.Fatalf("analyzer %s status = %q, want skipped (no contracts)", name, statuses[name])
		}
	}
}

func TestPipelineDeterministicAcrossRuns(t *testing.T) {
	dir := e2eDir(t)
	loader := NewLoader()
	opts := Options{Dir: dir, Loader: loader, MaxParallel: 4}

	res1, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run 1: %v", err)
	}
	res2, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run 2: %v", err)
	}
	if loader.Loads() != 1 {
		t.Fatalf("loader performed %d loads across two runs, want 1 (cache)", loader.Loads())
	}

	// Analyzer ordering and finding IDs must be identical across runs.
	if len(res1.Analyzers) != len(res2.Analyzers) {
		t.Fatal("analyzer count differs between runs")
	}
	for i := range res1.Analyzers {
		if res1.Analyzers[i].Name != res2.Analyzers[i].Name ||
			res1.Analyzers[i].Status != res2.Analyzers[i].Status {
			t.Fatalf("analyzer %d differs: %+v vs %+v", i, res1.Analyzers[i], res2.Analyzers[i])
		}
	}
	if len(res1.Findings) != len(res2.Findings) {
		t.Fatalf("finding count differs: %d vs %d", len(res1.Findings), len(res2.Findings))
	}
	for i := range res1.Findings {
		if res1.Findings[i].ID != res2.Findings[i].ID {
			t.Fatalf("finding %d ID differs: %s vs %s", i, res1.Findings[i].ID, res2.Findings[i].ID)
		}
	}
}

func TestPipelineSubsetOfAnalyzers(t *testing.T) {
	dir := e2eDir(t)
	res, err := Run(context.Background(), Options{
		Dir:       dir,
		Analyzers: []string{AnalyzerTypeState},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Analyzers) != 1 || res.Analyzers[0].Name != AnalyzerTypeState {
		t.Fatalf("expected only typestate analyzer, got %+v", res.Analyzers)
	}
}
