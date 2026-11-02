package review

import "testing"

func TestIsValidRunID(t *testing.T) {
	tests := []struct {
		name  string
		runID string
		want  bool
	}{
		{"valid", "08d28520b0879cee", true},
		{"too short", "08d28520", false},
		{"too long", "08d28520b0879cee00", false},
		{"invalid characters", "08d28520b0879ceg", false},
		{"uppercase", "08D28520B0879CEE", false},
		{"path traversal", "../../etc/passwd", false},
		{"empty", "", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := IsValidRunID(test.runID)
			if got != test.want {
				t.Errorf("IsValidRunID(%q) = %v, want %v", test.runID, got, test.want)
			}
		})
	}
}
