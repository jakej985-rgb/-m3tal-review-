package review

import (
	"testing"
)

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input      string
		wantNorm   string
		wantRawSev string
	}{
		{"CRITICAL", "critical", "CRITICAL"},
		{"fatal", "critical", "fatal"},
		{"Blocker", "critical", "Blocker"},
		{"HIGH", "high", "HIGH"},
		{"error", "high", "error"},
		{"MEDIUM", "medium", "MEDIUM"},
		{"Moderate", "medium", "Moderate"},
		{"WARN", "medium", "WARN"},
		{"warning", "medium", "warning"},
		{"LOW", "low", "LOW"},
		{"minor", "low", "minor"},
		{"INFO", "info", "INFO"},
		{"informational", "info", "informational"},
		{"note", "info", "note"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{"9.8", "critical", "9.8"},
		{"7.5", "high", "7.5"},
		{"5.0", "medium", "5.0"},
		{"2.5", "low", "2.5"},
		{"0.0", "info", "0.0"},
		{"none", "info", "none"},
		{"negligible", "info", "negligible"},
		{"very_high", "critical", "very_high"},
		{"score: 9.1", "critical", "score: 9.1"},
		{"", "medium", ""},
	}

	for _, tc := range tests {
		gotNorm, gotRaw := NormalizeSeverity(tc.input)
		if gotNorm != tc.wantNorm {
			t.Errorf("NormalizeSeverity(%q) norm = %q, want %q", tc.input, gotNorm, tc.wantNorm)
		}
		if gotRaw != tc.wantRawSev {
			t.Errorf("NormalizeSeverity(%q) raw = %q, want %q", tc.input, gotRaw, tc.wantRawSev)
		}
	}
}

func TestNormalizeConfidence(t *testing.T) {
	tests := []struct {
		input       string
		wantNorm    string
		wantRawConf string
	}{
		{"HIGH", "high", "HIGH"},
		{"Certain", "high", "Certain"},
		{"definite", "high", "definite"},
		{"MEDIUM", "medium", "MEDIUM"},
		{"Moderate", "medium", "Moderate"},
		{"likely", "medium", "likely"},
		{"LOW", "low", "LOW"},
		{"Unconfirmed", "low", "Unconfirmed"},
		{"experimental", "low", "experimental"},
		{"unknown-conf", "medium", "unknown-conf"},
		{"", "medium", ""},
	}

	for _, tc := range tests {
		gotNorm, gotRaw := NormalizeConfidence(tc.input)
		if gotNorm != tc.wantNorm {
			t.Errorf("NormalizeConfidence(%q) norm = %q, want %q", tc.input, gotNorm, tc.wantNorm)
		}
		if gotRaw != tc.wantRawConf {
			t.Errorf("NormalizeConfidence(%q) raw = %q, want %q", tc.input, gotRaw, tc.wantRawConf)
		}
	}
}

func TestMaxSeverityAndConfidence(t *testing.T) {
	if got := MaxSeverity("low", "critical"); got != "critical" {
		t.Fatalf("MaxSeverity = %q, want critical", got)
	}
	if got := MaxSeverity("high", "medium"); got != "high" {
		t.Fatalf("MaxSeverity = %q, want high", got)
	}
	if got := MaxConfidence("low", "high"); got != "high" {
		t.Fatalf("MaxConfidence = %q, want high", got)
	}
}
