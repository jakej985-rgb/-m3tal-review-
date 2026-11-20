package review

import "testing"

func TestComputeGradeEmpty(t *testing.T) {
	r := ComputeGrade(nil)
	if r.Score != 100 {
		t.Errorf("empty findings: want score=100, got %d", r.Score)
	}
	if r.Grade != "A" {
		t.Errorf("empty findings: want grade=A, got %s", r.Grade)
	}
	if r.TotalPenalty != 0 {
		t.Errorf("empty findings: want penalty=0, got %d", r.TotalPenalty)
	}
}

func TestComputeGradeInfoOnly(t *testing.T) {
	findings := []Finding{
		{Severity: "info"},
		{Severity: "info", Confidence: "high"},
	}
	r := ComputeGrade(findings)
	if r.Score != 100 {
		t.Errorf("info-only: want score=100, got %d", r.Score)
	}
	if r.Grade != "A" {
		t.Errorf("info-only: want grade=A, got %s", r.Grade)
	}
}

func TestComputeGradeSingleCritical(t *testing.T) {
	findings := []Finding{
		{Severity: "critical", Confidence: "high"},
	}
	r := ComputeGrade(findings)
	// penalty = 25 * 1.0 = 25; score = 75; grade = B
	if r.Score != 75 {
		t.Errorf("single critical/high: want score=75, got %d", r.Score)
	}
	if r.Grade != "B" {
		t.Errorf("single critical/high: want grade=B, got %s", r.Grade)
	}
	if r.TotalPenalty != 25 {
		t.Errorf("single critical/high: want penalty=25, got %d", r.TotalPenalty)
	}
}

func TestComputeGradeMediumConfidence(t *testing.T) {
	findings := []Finding{
		{Severity: "critical", Confidence: "medium"},
	}
	r := ComputeGrade(findings)
	// penalty = round(25 * 0.75) = 19; score = 81; grade = B
	if r.Score != 81 {
		t.Errorf("critical/medium: want score=81, got %d", r.Score)
	}
	if r.Grade != "B" {
		t.Errorf("critical/medium: want grade=B, got %s", r.Grade)
	}
}

func TestComputeGradeLowConfidence(t *testing.T) {
	findings := []Finding{
		{Severity: "critical", Confidence: "low"},
	}
	r := ComputeGrade(findings)
	// penalty = round(25 * 0.5) = 13; score = 87; grade = B
	if r.Score != 87 {
		t.Errorf("critical/low: want score=87, got %d", r.Score)
	}
}

func TestComputeGradeThresholds(t *testing.T) {
	cases := []struct {
		findings  []Finding
		wantGrade string
	}{
		// A: 1 medium/high → penalty=4; score=96
		{[]Finding{{Severity: "medium", Confidence: "high"}}, "A"},
		// B: 3 high/high → penalty=30; score=70
		{[]Finding{
			{Severity: "high", Confidence: "high"},
			{Severity: "high", Confidence: "high"},
			{Severity: "high", Confidence: "high"},
		}, "C"},
		// D: 4 critical/high → penalty=100 (capped); score=0; grade=F
		{[]Finding{
			{Severity: "critical", Confidence: "high"},
			{Severity: "critical", Confidence: "high"},
			{Severity: "critical", Confidence: "high"},
			{Severity: "critical", Confidence: "high"},
			{Severity: "critical", Confidence: "high"},
		}, "F"},
	}
	for _, tc := range cases {
		r := ComputeGrade(tc.findings)
		if r.Grade != tc.wantGrade {
			t.Errorf("findings %v: want grade=%s, got grade=%s (score=%d)", tc.findings, tc.wantGrade, r.Grade, r.Score)
		}
	}
}

func TestComputeGradeCapAt100Penalty(t *testing.T) {
	// 10 criticals at high confidence = 250 raw penalty; must be capped at 100.
	findings := make([]Finding, 10)
	for i := range findings {
		findings[i] = Finding{Severity: "critical", Confidence: "high"}
	}
	r := ComputeGrade(findings)
	if r.TotalPenalty != 100 {
		t.Errorf("cap test: want penalty=100, got %d", r.TotalPenalty)
	}
	if r.Score != 0 {
		t.Errorf("cap test: want score=0, got %d", r.Score)
	}
	if r.Grade != "F" {
		t.Errorf("cap test: want grade=F, got %s", r.Grade)
	}
}

func TestComputeGradeCountsAccurate(t *testing.T) {
	findings := []Finding{
		{Severity: "critical"},
		{Severity: "high"},
		{Severity: "high"},
		{Severity: "medium"},
		{Severity: "low"},
		{Severity: "info"},
	}
	r := ComputeGrade(findings)
	if r.FindingCounts["critical"] != 1 {
		t.Errorf("critical count: got %d, want 1", r.FindingCounts["critical"])
	}
	if r.FindingCounts["high"] != 2 {
		t.Errorf("high count: got %d, want 2", r.FindingCounts["high"])
	}
	if r.FindingCounts["medium"] != 1 {
		t.Errorf("medium count: got %d, want 1", r.FindingCounts["medium"])
	}
	if r.FindingCounts["low"] != 1 {
		t.Errorf("low count: got %d, want 1", r.FindingCounts["low"])
	}
	if r.FindingCounts["info"] != 1 {
		t.Errorf("info count: got %d, want 1", r.FindingCounts["info"])
	}
}

func TestComputeGradeEmptySeverityDefaultsMedium(t *testing.T) {
	// A finding with no severity should be treated as medium.
	findings := []Finding{{Severity: "", Confidence: "high"}}
	r := ComputeGrade(findings)
	// medium/high penalty = 4; score=96; grade=A
	if r.TotalPenalty != 4 {
		t.Errorf("empty severity: want penalty=4, got %d", r.TotalPenalty)
	}
	if r.FindingCounts["medium"] != 1 {
		t.Errorf("empty severity: should count as medium")
	}
}

func TestScoreToGrade(t *testing.T) {
	cases := []struct {
		score int
		grade string
	}{
		{100, "A"}, {90, "A"}, {89, "B"}, {75, "B"}, {74, "C"},
		{60, "C"}, {59, "D"}, {40, "D"}, {39, "F"}, {0, "F"},
	}
	for _, tc := range cases {
		got := scoreToGrade(tc.score)
		if got != tc.grade {
			t.Errorf("scoreToGrade(%d): want %s, got %s", tc.score, tc.grade, got)
		}
	}
}
