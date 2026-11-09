package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSemverAndCompatibility(t *testing.T) {
	cases := []struct {
		output     string
		wantVer    string
		wantMaj    int
		wantMin    int
		wantPatch  int
		shouldPass bool
	}{
		{"8.18.2", "8.18.2", 8, 18, 2, true},
		{"v8.0.0", "8.0.0", 8, 0, 0, true},
		{"gitleaks version 8.16.0", "8.16.0", 8, 16, 0, true},
		{"Gosec  : 2.18.2\nGit tag: v2.18.2", "2.18.2", 2, 18, 2, true},
		{"osv-scanner version 1.6.2 (commit ...)", "1.6.2", 1, 6, 2, true},
		{"version 1.0", "1.0.0", 1, 0, 0, true},
		{"not-a-version", "", 0, 0, 0, false},
	}

	for _, c := range cases {
		verStr, maj, min, patch, err := parseSemver(c.output)
		if c.shouldPass {
			if err != nil {
				t.Errorf("parseSemver(%q) unexpected error: %v", c.output, err)
			}
			if verStr != c.wantVer || maj != c.wantMaj || min != c.wantMin || patch != c.wantPatch {
				t.Errorf("parseSemver(%q) = (%s, %d, %d, %d), want (%s, %d, %d, %d)", c.output, verStr, maj, min, patch, c.wantVer, c.wantMaj, c.wantMin, c.wantPatch)
			}
		} else {
			if err == nil {
				t.Errorf("parseSemver(%q) expected error, got nil", c.output)
			}
		}
	}

	// Compatibility checks
	compatTests := []struct {
		actual   string
		required string
		expected bool
	}{
		{"8.18.2", "8.0.0", true},
		{"8.0.0", "8.0.0", true},
		{"7.9.9", "8.0.0", false},
		{"2.14.0", "2.0.0", true},
		{"1.9.9", "2.0.0", false},
		{"1.0.0", "1.0.0", true},
		{"0.9.5", "1.0.0", false},
		{"9.0.0", "8.0.0", true},
	}

	for _, tc := range compatTests {
		compat, err := checkVersionCompatibility(tc.actual, tc.required)
		if err != nil {
			t.Errorf("checkVersionCompatibility(%q, %q) error: %v", tc.actual, tc.required, err)
		}
		if compat != tc.expected {
			t.Errorf("checkVersionCompatibility(%q, %q) = %v, want %v", tc.actual, tc.required, compat, tc.expected)
		}
	}
}

func TestResolveToolExecutablePrecedence(t *testing.T) {
	tempDir := t.TempDir()

	// Create dummy executable script
	createScript := func(name string) string {
		path := filepath.Join(tempDir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
			t.Fatal(err)
		}
		return path
	}

	scriptFlag := createScript("flag-gitleaks")
	scriptEnv := createScript("env-gitleaks")

	// 1. Explicit override in map takes precedence
	overrides := map[string]string{
		"gitleaks": scriptFlag,
	}
	t.Setenv("M3TAL_GITLEAKS_PATH", scriptEnv)

	resolved, isExplicit, err := resolveToolExecutable("gitleaks", overrides)
	if err != nil {
		t.Fatalf("resolveToolExecutable failed: %v", err)
	}
	if !isExplicit || resolved != scriptFlag {
		t.Errorf("expected flag override %q, got resolved=%q, isExplicit=%v", scriptFlag, resolved, isExplicit)
	}

	// 2. Env var takes precedence when map override is absent
	delete(overrides, "gitleaks")
	resolvedEnv, isExplicitEnv, err := resolveToolExecutable("gitleaks", overrides)
	if err != nil {
		t.Fatalf("resolveToolExecutable with env failed: %v", err)
	}
	if !isExplicitEnv || resolvedEnv != scriptEnv {
		t.Errorf("expected env override %q, got resolved=%q, isExplicit=%v", scriptEnv, resolvedEnv, isExplicitEnv)
	}
}

func TestValidateExecutablePathErrors(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Non-existent file
	if err := validateExecutablePath(filepath.Join(tempDir, "nonexistent")); err == nil {
		t.Errorf("expected error for nonexistent file, got nil")
	}

	// 2. Directory
	dirPath := filepath.Join(tempDir, "adir")
	if err := os.Mkdir(dirPath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := validateExecutablePath(dirPath); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Errorf("expected directory error, got: %v", err)
	}

	// 3. Non-executable regular file
	noExec := filepath.Join(tempDir, "noexec")
	if err := os.WriteFile(noExec, []byte("echo hi"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := validateExecutablePath(noExec); err == nil || !strings.Contains(err.Error(), "not executable") {
		t.Errorf("expected not executable error, got: %v", err)
	}
}

func TestToolVersionCompatibilityEnforcement(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Incompatible version script: outputs gitleaks 7.1.0
	incompatScript := filepath.Join(tempDir, "mock-gitleaks-incompat")
	scriptContent := "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then echo \"7.1.0\"; exit 0; fi\nexit 0\n"
	if err := os.WriteFile(incompatScript, []byte(scriptContent), 0755); err != nil {
		t.Fatal(err)
	}

	overrides := map[string]string{
		"gitleaks": incompatScript,
	}

	findings, results := runOptionalLocalToolsWithOverrides(tempDir, overrides)
	var foundGitleaksCheck bool
	for _, res := range results {
		if res.Name == "gitleaks" {
			foundGitleaksCheck = true
			if res.Status != "unavailable" {
				t.Errorf("expected gitleaks status 'unavailable' for incompatible version, got %q", res.Status)
			}
			if !strings.Contains(res.Message, "incompatible version 7.1.0") || !strings.Contains(res.Message, "requires >= 8.0.0") {
				t.Errorf("expected message to explain version requirement, got: %s", res.Message)
			}
			if res.Version != "7.1.0" {
				t.Errorf("expected CheckResult.Version = 7.1.0, got %q", res.Version)
			}
			if res.Path != incompatScript {
				t.Errorf("expected CheckResult.Path = %q, got %q", incompatScript, res.Path)
			}
		}
	}
	if !foundGitleaksCheck {
		t.Errorf("expected gitleaks check result in output")
	}

	var foundIncompatFinding bool
	for _, f := range findings {
		if f.Rule == "tool-gitleaks" && f.Severity == "high" {
			foundIncompatFinding = true
			if !strings.Contains(f.Message, "incompatible") || !strings.Contains(f.Message, "requires >= 8.0.0") {
				t.Errorf("expected finding message to explain requirement, got: %s", f.Message)
			}
		}
	}
	if !foundIncompatFinding {
		t.Errorf("expected high-severity tool-gitleaks finding for incompatible version")
	}

	// 2. Compatible version script: outputs gitleaks 8.18.2
	compatScript := filepath.Join(tempDir, "mock-gitleaks-compat")
	compatContent := "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then echo \"8.18.2\"; exit 0; fi\nexit 0\n"
	if err := os.WriteFile(compatScript, []byte(compatContent), 0755); err != nil {
		t.Fatal(err)
	}

	overridesCompat := map[string]string{
		"gitleaks": compatScript,
	}
	findingsCompat, resultsCompat := runOptionalLocalToolsWithOverrides(tempDir, overridesCompat)
	for _, res := range resultsCompat {
		if res.Name == "gitleaks" {
			if res.Version != "8.18.2" {
				t.Errorf("expected recorded version 8.18.2, got %q", res.Version)
			}
			if res.Path != compatScript {
				t.Errorf("expected recorded path %q, got %q", compatScript, res.Path)
			}
			if res.Status != "passed" {
				t.Errorf("expected status 'passed', got %q (%s)", res.Status, res.Message)
			}
		}
	}
	for _, f := range findingsCompat {
		if f.Rule == "tool-gitleaks" {
			t.Errorf("unexpected tool-gitleaks failure finding for compatible tool: %+v", f)
		}
	}
}
