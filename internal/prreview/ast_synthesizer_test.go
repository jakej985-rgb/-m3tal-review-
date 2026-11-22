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

func TestPolyglotSymbolAndRouteExtraction(t *testing.T) {
	// 1. Python: changed line is on line 3, inside calculate_metrics() (line 1 is unchanged)
	pyCode := `async def calculate_metrics(data):
    total = sum(data)
    return total * 1.05
`
	pyChanged := map[int]bool{3: true}
	pySymbols := extractPythonSymbols([]byte(pyCode), pyChanged)
	if len(pySymbols) == 0 || pySymbols[0] != "calculate_metrics" {
		t.Errorf("expected calculate_metrics extracted from inner body change, got %+v", pySymbols)
	}

	// 2. TypeScript: changed line on line 3 inside saveUser()
	tsCode := `export class UserService {
    saveUser(user: User): boolean {
        return database.save(user);
    }
}
`
	tsChanged := map[int]bool{3: true}
	tsSymbols := extractJSTSSymbols([]byte(tsCode), tsChanged)
	foundUser := false
	for _, s := range tsSymbols {
		if s == "UserService" {
			foundUser = true
		}
	}
	if !foundUser {
		t.Errorf("expected UserService extracted from inner body change, got %+v", tsSymbols)
	}

	// 3. Java: Spring Boot route on line 1, method on line 2
	javaCode := `@GetMapping("/api/v1/items")
public List<Item> getItems() {
    return itemsService.findAll();
}
`
	javaChanged := map[int]bool{1: true, 3: true}
	javaSymbols := extractJavaSymbols([]byte(javaCode), javaChanged)
	foundRoute := false
	for _, s := range javaSymbols {
		if strings.Contains(s, "/api/v1/items") {
			foundRoute = true
		}
	}
	if !foundRoute {
		t.Errorf("expected GET /api/v1/items route extracted, got %+v", javaSymbols)
	}

	// 4. C#: Minimal API route on line 1
	csCode := `app.MapGet("/api/orders", () => Results.Ok());`
	csChanged := map[int]bool{1: true}
	csSymbols := extractCSharpSymbols([]byte(csCode), csChanged)
	foundCsRoute := false
	for _, s := range csSymbols {
		if strings.Contains(s, "/api/orders") {
			foundCsRoute = true
		}
	}
	if !foundCsRoute {
		t.Errorf("expected MapGet /api/orders route extracted, got %+v", csSymbols)
	}
}

