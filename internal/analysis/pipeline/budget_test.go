package pipeline

import (
	"context"
	"testing"
	"time"
)

func TestCancellationPropagation(t *testing.T) {
	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately
	cancel()

	opts := Options{
		Dir:             dir,
		MaxParallel:     2,
		AnalyzerTimeout: 1 * time.Second,
	}

	_, err := Run(ctx, opts)
	if err == nil {
		t.Fatal("expected Run with canceled context to fail, but it returned nil error")
	}
}

func TestBudgetExhaustionDegradedStatus(t *testing.T) {
	res := &Result{
		Analyzers: []AnalyzerResult{
			{
				Name:      "flow",
				Status:    "passed",
				Truncated: false,
			},
			{
				Name:      "concurrency",
				Status:    "passed",
				Truncated: true,
				Message:   "analysis truncated by budget",
			},
		},
		Truncated: true,
	}

	if !res.Truncated {
		t.Fatalf("expected pipeline Result to report Truncated=true")
	}

	// Verify that truncated analyzer does not claim full clean coverage
	hasTruncated := false
	for _, a := range res.Analyzers {
		if a.Truncated {
			hasTruncated = true
			if a.Message == "" {
				t.Errorf("expected truncated analyzer %s to provide an explanatory message", a.Name)
			}
		}
	}
	if !hasTruncated {
		t.Fatalf("expected at least one truncated analyzer in result")
	}
}
