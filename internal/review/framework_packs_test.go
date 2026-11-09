package review

import (
	"os"
	"path/filepath"
	"testing"
)

func diffForTest(file, code string) string {
	return "diff --git a/" + file + " b/" + file + "\n" +
		"--- a/" + file + "\n" +
		"+++ b/" + file + "\n" +
		"@@ -0,0 +1,1 @@\n" +
		"+" + code + "\n"
}

func TestDetectFrameworks(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Detection from go.mod
	goModContent := `module example.com/test
go 1.23
require (
	github.com/gin-gonic/gin v1.9.1
	github.com/labstack/echo/v4 v4.11.1
)
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goModContent), 0644); err != nil {
		t.Fatalf("failed to write go.mod: %v", err)
	}

	detected := DetectFrameworks(tmpDir, "")
	if len(detected) != 2 || detected[0] != FrameworkEcho || detected[1] != FrameworkGin {
		t.Fatalf("expected [echo, gin] from go.mod, got %v", detected)
	}

	// 2. Detection from diff imports
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -0,0 +1,4 @@
+import (
+	"github.com/go-chi/chi/v5"
+	"github.com/gofiber/fiber/v2"
+	"net/http"
+)
`
	detectedDiff := DetectFrameworks("", diff)
	expected := []string{FrameworkChi, FrameworkFiber, FrameworkNetHTTP}
	if len(detectedDiff) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, detectedDiff)
	}
	for i, exp := range expected {
		if detectedDiff[i] != exp {
			t.Errorf("at index %d: expected %s, got %s", i, exp, detectedDiff[i])
		}
	}
}

func TestResolveFrameworkPacks(t *testing.T) {
	// Explicit requested packs
	packs, rules, checks := ResolveFrameworkPacks("", "", []string{"gin", "echo"})
	if len(packs) != 2 {
		t.Fatalf("expected 2 packs, got %d", len(packs))
	}
	if len(checks) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(checks))
	}
	if checks[0].Name != "framework:gin" || checks[0].Category != "framework" || checks[0].Status != "passed" {
		t.Errorf("unexpected check[0]: %+v", checks[0])
	}
	if checks[1].Name != "framework:echo" || checks[1].Version != FrameworkPackVersion {
		t.Errorf("unexpected check[1]: %+v", checks[1])
	}
	if len(rules) == 0 {
		t.Errorf("expected rules to be populated")
	}

	// Requested "all"
	allPacks, allRules, allChecks := ResolveFrameworkPacks("", "", []string{"all"})
	if len(allPacks) != 5 || len(allChecks) != 5 || len(allRules) == 0 {
		t.Errorf("expected 5 packs for 'all', got %d packs, %d checks", len(allPacks), len(allChecks))
	}

	// Requested "none"
	nonePacks, noneRules, noneChecks := ResolveFrameworkPacks("", "", []string{"none"})
	if len(nonePacks) != 0 || len(noneRules) != 0 || len(noneChecks) != 0 {
		t.Errorf("expected 0 packs for 'none', got %d", len(nonePacks))
	}
}

func TestGinPackRules(t *testing.T) {
	pack := GinPack("")
	engine := NewEngine(pack.Rules...)

	// Positive test cases
	testCases := []struct {
		name     string
		code     string
		expected string
	}{
		{
			name:     "unhandled binding",
			code:     "_ = c.BindJSON(&req)",
			expected: "gin-unhandled-binding",
		},
		{
			name:     "unhandled should bind",
			code:     "c.ShouldBindJSON(&req)",
			expected: "gin-unhandled-binding",
		},
		{
			name:     "wildcard cors",
			code:     "cors.Default()",
			expected: "gin-wildcard-cors",
		},
		{
			name:     "missing recovery",
			code:     "router := gin.New()",
			expected: "gin-missing-recovery",
		},
		{
			name:     "unsafe param reflection",
			code:     "c.String(200, c.Param(\"id\"))",
			expected: "gin-unsafe-param-reflection",
		},
		{
			name:     "debug mode",
			code:     "gin.SetMode(gin.DebugMode)",
			expected: "gin-debug-mode",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			diff := diffForTest("handler.go", tc.code)
			findings := engine.Run(diff)
			found := false
			for _, f := range findings {
				if f.Rule == tc.expected {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected rule %q to fire for code %q, got: %+v", tc.expected, tc.code, findings)
			}
		})
	}

	// Negative test cases (handled binding, safe param handling)
	safeDiff := diffForTest("handler.go", `if err := c.ShouldBindJSON(&req); err != nil { return }
c.JSON(200, req)`)
	findings := engine.Run(safeDiff)
	for _, f := range findings {
		if f.Rule == "gin-unhandled-binding" || f.Rule == "gin-unsafe-param-reflection" {
			t.Errorf("unexpected finding on safe code: %+v", f)
		}
	}
}

func TestEchoPackRules(t *testing.T) {
	pack := EchoPack("")
	engine := NewEngine(pack.Rules...)

	testCases := []struct {
		name     string
		code     string
		expected string
	}{
		{
			name:     "unhandled binding",
			code:     "_ = c.Bind(&req)",
			expected: "echo-unhandled-binding",
		},
		{
			name:     "wildcard cors",
			code:     `e.Use(middleware.CORSWithConfig(middleware.CORSConfig{AllowOrigins: []string{"*"}, AllowCredentials: true}))`,
			expected: "echo-wildcard-cors",
		},
		{
			name:     "missing recovery",
			code:     "e := echo.New()",
			expected: "echo-missing-recovery",
		},
		{
			name:     "unsafe param reflection",
			code:     "return c.HTML(200, c.Param(\"id\"))",
			expected: "echo-unsafe-param-reflection",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			diff := diffForTest("handler.go", tc.code)
			findings := engine.Run(diff)
			found := false
			for _, f := range findings {
				if f.Rule == tc.expected {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected rule %q to fire for code %q, got: %+v", tc.expected, tc.code, findings)
			}
		})
	}
}

func TestChiPackRules(t *testing.T) {
	pack := ChiPack("")
	engine := NewEngine(pack.Rules...)

	testCases := []struct {
		name     string
		code     string
		expected string
	}{
		{
			name:     "unhandled binding",
			code:     "_ = render.Bind(r, &req)",
			expected: "chi-unhandled-binding",
		},
		{
			name:     "wildcard cors",
			code:     `cors.Handler(cors.Options{AllowedOrigins: []string{"*"}, AllowCredentials: true})`,
			expected: "chi-wildcard-cors",
		},
		{
			name:     "missing recovery",
			code:     "r := chi.NewRouter()",
			expected: "chi-missing-recovery",
		},
		{
			name:     "unsafe param reflection",
			code:     "w.Write([]byte(chi.URLParam(r, \"id\")))",
			expected: "chi-unsafe-param-reflection",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			diff := diffForTest("handler.go", tc.code)
			findings := engine.Run(diff)
			found := false
			for _, f := range findings {
				if f.Rule == tc.expected {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected rule %q to fire for code %q, got: %+v", tc.expected, tc.code, findings)
			}
		})
	}
}

func TestFiberPackRules(t *testing.T) {
	pack := FiberPack("")
	engine := NewEngine(pack.Rules...)

	testCases := []struct {
		name     string
		code     string
		expected string
	}{
		{
			name:     "unhandled binding",
			code:     "_ = c.BodyParser(&req)",
			expected: "fiber-unhandled-binding",
		},
		{
			name:     "wildcard cors",
			code:     `cors.New(cors.Config{AllowOrigins: "*", AllowCredentials: true})`,
			expected: "fiber-wildcard-cors",
		},
		{
			name:     "missing recovery",
			code:     "app := fiber.New()",
			expected: "fiber-missing-recovery",
		},
		{
			name:     "unsafe param reflection",
			code:     "return c.SendString(c.Params(\"id\"))",
			expected: "fiber-unsafe-param-reflection",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			diff := diffForTest("handler.go", tc.code)
			findings := engine.Run(diff)
			found := false
			for _, f := range findings {
				if f.Rule == tc.expected {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected rule %q to fire for code %q, got: %+v", tc.expected, tc.code, findings)
			}
		})
	}
}

func TestNetHTTPPackRules(t *testing.T) {
	pack := NetHTTPPack("")
	engine := NewEngine(pack.Rules...)

	testCases := []struct {
		name     string
		code     string
		expected string
	}{
		{
			name:     "unhandled body read",
			code:     "_ = json.NewDecoder(r.Body).Decode(&req)",
			expected: "http-unhandled-body-read",
		},
		{
			name:     "wildcard cors",
			code:     `w.Header().Set("Access-Control-Allow-Origin", "*"); w.Header().Set("Access-Control-Allow-Credentials", "true")`,
			expected: "http-wildcard-cors",
		},
		{
			name:     "missing timeouts",
			code:     `http.ListenAndServe(":8080", nil)`,
			expected: "http-missing-timeouts",
		},
		{
			name:     "unsafe param reflection",
			code:     `w.Write([]byte(r.URL.Query().Get("user")))`,
			expected: "http-unsafe-param-reflection",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			diff := diffForTest("handler.go", tc.code)
			findings := engine.Run(diff)
			found := false
			for _, f := range findings {
				if f.Rule == tc.expected {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected rule %q to fire for code %q, got: %+v", tc.expected, tc.code, findings)
			}
		})
	}
}
