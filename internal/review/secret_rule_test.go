package review

import (
	"strings"
	"testing"
)

func TestSecretRuleFindsPrivateKeyAndTokens(t *testing.T) {
	diff := `diff --git a/config.go b/config.go
--- a/config.go
+++ b/config.go
@@ -0,0 +1,9 @@
+package main
+
+const awsKey = "AKIA1234567890ABCDEF"
+const openaiKey = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
+// AKIA1234567890ABCDEF mentioned in a comment is skipped
+const placeholder = "github_pat_example_notarealtoken1234567890"
+const pem = ` + "`" + `
+-----BEGIN RSA PRIVATE KEY-----
+` + "`" + `
`
	findings := (SecretRule{}).Check(diff)
	var aws, openai, pemCount int
	for _, f := range findings {
		if f.File != "config.go" {
			t.Fatalf("unexpected file %q", f.File)
		}
		switch {
		case f.Message == "Possible exposed credential: aws token":
			aws++
		case f.Message == "Possible exposed credential: openai token":
			openai++
		case f.Message == "Private key material appears in the change":
			pemCount++
		default:
			t.Fatalf("unexpected finding: %+v", f)
		}
	}
	if aws != 1 || openai != 1 || pemCount != 1 {
		t.Fatalf("aws=%d openai=%d pem=%d; want 1 each (findings: %+v)", aws, openai, pemCount, findings)
	}
}

func TestSecretRuleDoesNotLeakTokenValue(t *testing.T) {
	diff := `diff --git a/a.go b/a.go
--- a/a.go
+++ b/a.go
@@ -0,0 +1 @@
+const k = "AKIA1234567890ABCDEF"
`
	findings := (SecretRule{}).Check(diff)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v; want 1", findings)
	}
	if strings.Contains(findings[0].Message, "AKIA1234567890ABCDEF") {
		t.Fatalf("finding leaks the secret value: %+v", findings[0])
	}
}
