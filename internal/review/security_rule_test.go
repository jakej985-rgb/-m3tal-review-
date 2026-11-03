package review

import "testing"

func TestSecurityRuleFindsHardcodedCredentials(t *testing.T) {
	diff := `diff --git a/config.go b/config.go
--- a/config.go
+++ b/config.go
@@ -1,1 +1,3 @@
 package main
+password = "supersecretpassword"
+api_key = "abc123456789"
`

	findings := (SecurityRule{}).Check(diff)

	if len(findings) != 2 {
		t.Fatalf("Check() returned %d findings, want 2: %+v", len(findings), findings)
	}

	for i, finding := range findings {
		if finding.Rule != "hardcoded-credential" {
			t.Errorf("finding[%d].Rule = %q, want %q", i, finding.Rule, "hardcoded-credential")
		}
		if finding.Severity != "high" {
			t.Errorf("finding[%d].Severity = %q, want %q", i, finding.Severity, "high")
		}
		if finding.File != "config.go" {
			t.Errorf("finding[%d].File = %q, want %q", i, finding.File, "config.go")
		}
		if finding.Line != i+2 {
			t.Errorf("finding[%d].Line = %d, want %d", i, finding.Line, i+2)
		}
	}
}

func TestSecurityRuleIgnoresPlaceholdersAndUnchangedLines(t *testing.T) {
	diff := `diff --git a/config.go b/config.go
--- a/config.go
+++ b/config.go
@@ -1,2 +1,2 @@
-password = "oldsecretvalue"
+password = "YOUR_API_KEY_HERE"
+token = "changeme"
 secret = "unchangedsecretvalue"
`

	findings := (SecurityRule{}).Check(diff)

	if len(findings) != 0 {
		t.Errorf("Check() returned findings for placeholders or unchanged lines: %+v", findings)
	}
}

func TestSecurityRuleName(t *testing.T) {
	if got := (SecurityRule{}).Name(); got != "hardcoded-credential" {
		t.Errorf("Name() = %q, want %q", got, "hardcoded-credential")
	}
}

func TestSecurityRuleFindsCredentialNameVariantsAndNormalizesQuotedPaths(t *testing.T) {
	diff := `diff --git "a/config with spaces.go" "b/config with spaces.go"
--- "a/config with spaces.go"
+++ "b/config with spaces.go"
@@ -0,0 +1,3 @@
+token := "a-real-token-value"
+clientSecret := "a-real-secret-value"
+refresh-token = "another-real-secret"
`

	findings := (SecurityRule{}).Check(diff)
	if len(findings) != 3 {
		t.Fatalf("Check() returned %d findings, want 3: %+v", len(findings), findings)
	}
	for i, finding := range findings {
		if finding.File != "config with spaces.go" {
			t.Errorf("finding[%d].File = %q, want normalized path", i, finding.File)
		}
		if finding.Line != i+1 {
			t.Errorf("finding[%d].Line = %d, want %d", i, finding.Line, i+1)
		}
	}
}

func credentialDiff(file, line string) string {
	return "diff --git a/" + file + " b/" + file + "\n--- a/" + file + "\n+++ b/" + file + "\n@@ -0,0 +1,1 @@\n+" + line + "\n"
}

func TestSecurityRuleFindsPreviouslyMissedShapes(t *testing.T) {
	tests := []struct {
		name string
		file string
		line string
	}{
		{"typed var", "a.go", `var dbPassword string = "hunter2hunter2"`},
		{"json key", "a.json", `"api_token": "abcd1234efgh5678"`},
		{"raw string", "a.go", "apiToken := `abcd1234efgh5678`"},
		{"env unquoted", ".env", `API_TOKEN=abcd1234efgh5678`},
		{"env export", "prod.env", `export DB_PASSWORD=hunter2hunter2`},
		{"yaml unquoted", "config.yaml", `password: hunter2hunter2`},
		{"example inside real secret", "a.go", `password = "real_example_secret_99"`},
		{"plus-plus prefixed line", "a.txt", `++password = "hunter2hunter2"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := (SecurityRule{}).Check(credentialDiff(tt.file, tt.line))
			if len(findings) != 1 {
				t.Fatalf("Check() returned %d findings, want 1: %+v", len(findings), findings)
			}
		})
	}
}

func TestSecurityRuleIgnoresNonSecrets(t *testing.T) {
	tests := []struct {
		name string
		file string
		line string
	}{
		{"getenv call in go", "a.go", `apiToken := os.Getenv("API_TOKEN")`},
		{"unquoted code outside config files", "a.go", `password: hunter2hunter2`},
		{"env substitution", ".env", `API_TOKEN=${API_TOKEN_FROM_CI}`},
		{"template value", "config.yaml", `password: {{ vault_password }}`},
		{"example prefix", "a.go", `password = "example-password"`},
		{"masked", "a.go", `password = "xxxxxxxx"`},
		{"short value", "a.go", `password = "short"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if findings := (SecurityRule{}).Check(credentialDiff(tt.file, tt.line)); len(findings) != 0 {
				t.Fatalf("Check() returned findings, want none: %+v", findings)
			}
		})
	}
}
