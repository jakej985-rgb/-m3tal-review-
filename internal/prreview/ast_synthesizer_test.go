package prreview

import (
	"strings"
	"testing"
)

func TestClassifyTaxonomy(t *testing.T) {
	cases := []struct {
		path     string
		expected TaxonomyCategory
	}{
		{"pkg/auth/jwt.go", TaxonomySecurityAndAuth},
		{"api/v1/router.go", TaxonomyArchAndAPI},
		{"internal/service/order.go", TaxonomyCoreLogic},
		{"go.mod", TaxonomyDepsAndConfig},
		{"internal/service/order_test.go", TaxonomyTestsAndTooling},
		{".github/workflows/ci.yml", TaxonomyTestsAndTooling},
	}

	for _, c := range cases {
		got := classifyTaxonomy(c.path)
		if got != c.expected {
			t.Errorf("classifyTaxonomy(%s) = %s, expected %s", c.path, got, c.expected)
		}
	}
}

func TestExtractGoSymbols(t *testing.T) {
	code := `package auth

type SessionManager struct {
	token string
}

func (s *SessionManager) ValidateToken(t string) bool {
	return t != ""
}

func CreateToken(user string) string {
	return "token"
}
`

	changedLines := map[int]bool{
		7:  true, // SessionManager.ValidateToken
		8:  true,
		12: true, // CreateToken
	}

	symbols := extractGoSymbols([]byte(code), changedLines)
	if len(symbols) != 2 {
		t.Fatalf("expected 2 symbols, got %d: %+v", len(symbols), symbols)
	}

	expected := map[string]bool{
		"(*SessionManager).ValidateToken": true,
		"CreateToken":                     true,
	}
	for _, sym := range symbols {
		if !expected[sym] {
			t.Errorf("unexpected symbol extracted: %s", sym)
		}
	}
}

func TestSynthesizeChanges(t *testing.T) {
	diffText := `diff --git a/pkg/auth/token.go b/pkg/auth/token.go
--- a/pkg/auth/token.go
+++ b/pkg/auth/token.go
@@ -5,4 +5,8 @@ package auth
+func ValidateToken(t string) bool {
+	return t != ""
+}
`
	files, err := ParseUnifiedDiff(diffText)
	if err != nil {
		t.Fatalf("parse diff: %v", err)
	}

	code := `package auth

func ValidateToken(t string) bool {
	return t != ""
}
`
	readFile := func(path string) ([]byte, error) {
		if path == "pkg/auth/token.go" {
			return []byte(code), nil
		}
		return nil, nil
	}

	synth := SynthesizeChanges(files, readFile)
	if synth.TotalFiles != 1 {
		t.Errorf("expected 1 file, got %d", synth.TotalFiles)
	}
	if len(synth.Files) != 1 {
		t.Fatalf("expected 1 file summary, got %d", len(synth.Files))
	}

	fs := synth.Files[0]
	if fs.Category != TaxonomySecurityAndAuth {
		t.Errorf("expected Security & Auth, got %s", fs.Category)
	}
	if fs.Risk != "High" {
		t.Errorf("expected High risk for auth file, got %s", fs.Risk)
	}
	if !strings.Contains(fs.SummaryText, "ValidateToken") {
		t.Errorf("expected summary to contain ValidateToken, got %s", fs.SummaryText)
	}
}
