package review

import (
	"strings"
	"testing"
)

func TestShannonEntropyCalculation(t *testing.T) {
	tests := []struct {
		input       string
		wantMin     float64
		wantMax     float64
		description string
	}{
		{"", 0.0, 0.0, "empty string"},
		{"aaaaaaaaaaaaaaaa", 0.0, 0.0, "single char repeated"},
		{"abababababababab", 0.99, 1.01, "binary alternation"},
		// 16 distinct hex chars: 0123456789abcdef -> log2(16) = 4.0
		{"0123456789abcdef0123456789abcdef", 3.99, 4.01, "uniform hex"},
		// High-entropy random hex token
		{"4f7a9c8b2e1d0f5a3b6c8e9d1a2f4b7c", 3.2, 4.0, "random hex secret"},
		// Standard English prose / camel case (~3.0-4.5)
		{"ThisIsAVeryLongFunctionNameThatDoesSomethingImportant", 3.0, 4.5, "english camel case"},
	}

	for _, tt := range tests {
		got := ShannonEntropy(tt.input)
		if got < tt.wantMin || got > tt.wantMax {
			t.Errorf("ShannonEntropy(%q) = %f, want between %f and %f (%s)",
				tt.input, got, tt.wantMin, tt.wantMax, tt.description)
		}
	}
}

func makeDiff(file, code string) string {
	var sb strings.Builder
	sb.WriteString("diff --git a/" + file + " b/" + file + "\n")
	sb.WriteString("--- a/" + file + "\n")
	sb.WriteString("+++ b/" + file + "\n")
	sb.WriteString("@@ -1,0 +1," + strings.TrimSpace(string(rune('0'+strings.Count(code, "\n")+1))) + " @@\n")
	for _, line := range strings.Split(code, "\n") {
		sb.WriteString("+" + line + "\n")
	}
	return sb.String()
}

func TestEntropyRulePositives(t *testing.T) {
	rule := EntropyRule{}

	cases := []struct {
		name string
		file string
		code string
	}{
		{
			name: "Hex secret token in API key assignment",
			file: "config.go",
			code: `package main
const apiKey = "4f7a9c8b2e1d0f5a3b6c8e9d1a2f4b7c89abcdef"
`,
		},
		{
			name: "Base64 secret in client_secret assignment",
			file: "auth.py",
			code: `client_secret = "dGhpcy1pcy1hLXJlYWxseS1zZWNyZXQtdG9rZW4tMTIzNDU2Nzg5MA=="
`,
		},
		{
			name: "High entropy password in .env file",
			file: ".env",
			code: `DB_PASSWORD=v9X#mK2$pL8@zQ5*wR1!yT4^bN7&jH3%
`,
		},
		{
			name: "Private key token assignment",
			file: "secrets.yaml",
			code: `private_key: "K9#mQ2!xL8$zW5*tR1@yP4^bN7&jF3%cV6~"
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			diff := makeDiff(tc.file, tc.code)
			findings := rule.Check(diff)
			if len(findings) == 0 {
				t.Fatalf("expected high-entropy-secret finding for %s, got none", tc.name)
			}
			f := findings[0]
			if f.Rule != "high-entropy-secret" {
				t.Errorf("expected rule high-entropy-secret, got %q", f.Rule)
			}
			if f.Severity != "high" {
				t.Errorf("expected severity high, got %q", f.Severity)
			}
			if f.Category != "security" {
				t.Errorf("expected category security, got %q", f.Category)
			}
			// Sensitive material must NEVER be leaked in the finding message
			if strings.Contains(f.Message, "4f7a9c8b") || strings.Contains(f.Message, "dGhpcy1p") || strings.Contains(f.Message, "v9X#mK2") {
				t.Errorf("finding message leaks secret content: %s", f.Message)
			}
		})
	}
}

func TestEntropyRuleNegatives(t *testing.T) {
	rule := EntropyRule{}

	cases := []struct {
		name string
		file string
		code string
	}{
		{
			name: "UUID is not flagged",
			file: "user.go",
			code: `const UserID = "123e4567-e89b-12d3-a456-426614174000"
`,
		},
		{
			name: "Placeholder words are ignored",
			file: "test.go",
			code: `var api_key = "example_dummy_test_placeholder_secret_123456789"
`,
		},
		{
			name: "Low entropy strings in variable assignment",
			file: "config.go",
			code: `var token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
`,
		},
		{
			name: "Comments are skipped",
			file: "auth.go",
			code: `// api_key = "4f7a9c8b2e1d0f5a3b6c8e9d1a2f4b7c89abcdef"
`,
		},
		{
			name: "Standard code without secret context",
			file: "calc.go",
			code: `func CalculateSomethingUseful(inputValue string) string {
    return strings.TrimSpace(inputValue)
}
`,
		},
		{
			name: "Image data URL is not flagged",
			file: "styles.css",
			code: `background: url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==");
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			diff := makeDiff(tc.file, tc.code)
			findings := rule.Check(diff)
			if len(findings) > 0 {
				t.Errorf("expected no findings for %s, got: %+v", tc.name, findings)
			}
		})
	}
}

func TestEntropyRuleEdgeCases(t *testing.T) {
	rule := EntropyRule{}

	// Huge line (> 4096 chars) does not crash or hang
	hugeLine := "password = \"" + strings.Repeat("A1b!9x", 1000) + "\""
	diff := makeDiff("huge.go", hugeLine)
	findings := rule.Check(diff)
	// Must not panic, line is safely bounded and skipped or processed without OOM
	_ = findings

	// Empty diff
	findingsEmpty := rule.Check("")
	if len(findingsEmpty) != 0 {
		t.Errorf("expected 0 findings for empty diff, got %d", len(findingsEmpty))
	}
}
