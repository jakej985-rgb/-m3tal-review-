package lifecycle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestAdjudicateLifecycle_States(t *testing.T) {
	baseFinding := review.Finding{
		ID:       "f-base",
		Rule:     "flow-path-traversal",
		File:     "handler.go",
		Line:     20,
		Severity: "high",
		Snippet:  "os.Open(userInput)",
	}

	manifest := NewBaselineManifest([]review.Finding{baseFinding}, "sha-v1")

	// 1. Unchanged exact match
	resUnchanged := AdjudicateLifecycle([]review.Finding{baseFinding}, manifest, nil)
	if resUnchanged.UnchangedCount != 1 || resUnchanged.ActiveFindings[0].State != StateUnchanged {
		t.Errorf("expected 1 unchanged finding, got %+v", resUnchanged)
	}

	// 2. Line movement & reformatting (StateChanged, MatchHeuristic)
	movedFinding := review.Finding{
		ID:       "f-moved",
		Rule:     "flow-path-traversal",
		File:     "handler.go",
		Line:     32, // moved 12 lines down
		Severity: "high",
		Snippet:  "os.Open( userInput )", // extra spaces
	}
	resMoved := AdjudicateLifecycle([]review.Finding{movedFinding}, manifest, nil)
	if resMoved.ChangedCount != 1 || resMoved.ActiveFindings[0].State != StateChanged {
		t.Errorf("expected 1 changed finding on line drift, got %+v", resMoved)
	}
	if resMoved.ActiveFindings[0].Match != MatchHeuristic {
		t.Errorf("expected MatchHeuristic for drifted finding")
	}

	// 3. Severity changed
	sevChanged := baseFinding
	sevChanged.Severity = "critical"
	resSev := AdjudicateLifecycle([]review.Finding{sevChanged}, manifest, nil)
	if resSev.SeverityChangeCount != 1 || resSev.ActiveFindings[0].State != StateSeverityChanged {
		t.Errorf("expected StateSeverityChanged, got %+v", resSev)
	}

	// 4. Resolved
	resResolved := AdjudicateLifecycle(nil, manifest, nil)
	if resResolved.ResolvedCount != 1 || len(resResolved.ResolvedFindings) != 1 {
		t.Errorf("expected 1 resolved finding, got %+v", resResolved)
	}
}

func TestAdjudicateLifecycle_Reintroduced(t *testing.T) {
	finding := review.Finding{
		ID:       "f-old",
		Rule:     "race-condition",
		File:     "worker.go",
		Line:     40,
		Severity: "high",
		Snippet:  "count++",
	}

	manifest := NewBaselineManifest(nil, "sha-v2")
	history := []HistoryRecord{
		{
			ID:   "f-old",
			Rule: "race-condition",
			File: "worker.go",
		},
	}

	res := AdjudicateLifecycle([]review.Finding{finding}, manifest, history)
	if res.ReintroducedCount != 1 || res.ActiveFindings[0].State != StateReintroduced {
		t.Errorf("expected StateReintroduced, got %+v", res)
	}
}

func TestBaselinePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	finding := review.Finding{
		ID:       "f-test",
		Rule:     "flow-sqli",
		File:     "db.go",
		Line:     15,
		Severity: "critical",
	}
	manifest := NewBaselineManifest([]review.Finding{finding}, "commit-123")

	// 1. Initial save
	if err := SaveBaseline(path, manifest, false); err != nil {
		t.Fatalf("SaveBaseline failed: %v", err)
	}

	// 2. Overwrite safeguard
	if err := SaveBaseline(path, manifest, false); err == nil {
		t.Errorf("expected error when overwriting without allowOverwrite=true")
	}

	// 3. Load baseline
	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline failed: %v", err)
	}
	if len(loaded.Findings) != 1 || loaded.Findings[0].ID != "f-test" {
		t.Errorf("loaded unexpected findings: %+v", loaded)
	}

	// 4. Tampered integrity check
	tamperedData := []byte(`{
		"version": "1.0",
		"integrity_hash": "bad-hash",
		"findings": [{"id": "f-test", "rule": "flow-sqli", "file": "db.go", "line": 15, "severity": "critical"}]
	}`)
	tamperedPath := filepath.Join(dir, "tampered.json")
	if err := os.WriteFile(tamperedPath, tamperedData, 0644); err != nil {
		t.Fatal(err)
	}
	_, errTampered := LoadBaseline(tamperedPath)
	if errTampered == nil || !strings.Contains(errTampered.Error(), "integrity hash mismatch") {
		t.Errorf("expected integrity hash mismatch error, got %v", errTampered)
	}
}
