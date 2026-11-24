package differential

import (
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestDifferentialComparison(t *testing.T) {
	m3talFindings := []NormalizedFinding{
		{
			Tool: "m3tal-review",
			Rule: "hardcoded-secret",
			File: "internal/auth/login.go",
			Line: 10,
		},
		{
			Tool: "m3tal-review",
			Rule: "concurrency-check-then-act",
			File: "pkg/cache/cache.go",
			Line: 55,
		},
	}

	refFindings := []NormalizedFinding{
		{
			Tool: "reference-sec",
			Rule: "hardcoded-secret",
			File: "internal/auth/login.go",
			Line: 12, // slightly different line
		},
		{
			Tool: "reference-sec",
			Rule: "unhandled-error",
			File: "cmd/main.go",
			Line: 20,
		},
	}

	res := Compare("benchmark-case-1", m3talFindings, refFindings)

	if len(res.Agreements) != 1 {
		t.Fatalf("expected 1 agreement, got %d", len(res.Agreements))
	}
	if res.Agreements[0].Rule != "hardcoded-secret" {
		t.Errorf("expected agreement on hardcoded-secret, got %s", res.Agreements[0].Rule)
	}

	if len(res.M3talOnly) != 1 {
		t.Fatalf("expected 1 m3tal-only finding, got %d", len(res.M3talOnly))
	}
	if res.M3talOnly[0].Rule != "concurrency-check-then-act" {
		t.Errorf("expected m3tal-only rule concurrency-check-then-act, got %s", res.M3talOnly[0].Rule)
	}

	if len(res.ReferenceOnly) != 1 {
		t.Fatalf("expected 1 reference-only finding, got %d", len(res.ReferenceOnly))
	}
	if res.ReferenceOnly[0].Rule != "unhandled-error" {
		t.Errorf("expected reference-only rule unhandled-error, got %s", res.ReferenceOnly[0].Rule)
	}
}

func TestGroundTruthMetrics(t *testing.T) {
	groundTruth := []NormalizedFinding{
		{Rule: "rule-a", File: "a.go"},
		{Rule: "rule-b", File: "b.go"},
		{Rule: "rule-c", File: "c.go"},
	}

	// Actual detected: rule-a (TP), rule-b (TP), rule-x (FP), missed rule-c (FN)
	actual := []NormalizedFinding{
		{Rule: "rule-a", File: "a.go"},
		{Rule: "rule-b", File: "b.go"},
		{Rule: "rule-x", File: "x.go"},
	}

	metrics := EvaluateAgainstGroundTruth(actual, groundTruth)

	if metrics.TruePositives != 2 {
		t.Errorf("TP: expected 2, got %d", metrics.TruePositives)
	}
	if metrics.FalsePositives != 1 {
		t.Errorf("FP: expected 1, got %d", metrics.FalsePositives)
	}
	if metrics.FalseNegatives != 1 {
		t.Errorf("FN: expected 1, got %d", metrics.FalseNegatives)
	}

	// Mathematical expectation: precision is 2/3 (~0.6667), recall is 2/3 (~0.6667).
	if metrics.Precision < 0.66 || metrics.Precision > 0.67 {
		t.Errorf("unexpected precision: %f", metrics.Precision)
	}
	if metrics.Recall < 0.66 || metrics.Recall > 0.67 {
		t.Errorf("unexpected recall: %f", metrics.Recall)
	}
	if metrics.F1Score < 0.66 || metrics.F1Score > 0.67 {
		t.Errorf("unexpected F1: %f", metrics.F1Score)
	}
}

func TestNormalizeM3talFindings(t *testing.T) {
	findings := []review.Finding{
		{
			ID:       "0123456789abcdef",
			Rule:     "secret-key",
			Category: "security",
			File:     "config.go",
			Line:     15,
			Message:  "API key leak",
		},
	}

	norm := NormalizeM3talFindings(findings)
	if len(norm) != 1 {
		t.Fatalf("expected 1 normalized finding, got %d", len(norm))
	}
	if norm[0].Tool != "m3tal-review" {
		t.Errorf("tool mismatch: %s", norm[0].Tool)
	}
	if norm[0].Key() != "config.go:secret-key" {
		t.Errorf("key mismatch: %s", norm[0].Key())
	}
}
