package review

import (
	"testing"
)

func TestScopedTestDiscoveryRule(t *testing.T) {
	rule := ScopedTestDiscoveryRule{}

	t.Run("flags broad test discovery in release preflight quality gate", func(t *testing.T) {
		diff := `diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh
--- a/scripts/quality_gate.sh
+++ b/scripts/quality_gate.sh
@@ -65,5 +65,5 @@ echo "[10/11] Verifying changelog..."
 
 echo "[11/11] Running release-tool unit tests..."
+python3 -m unittest discover -s test/scripts -p 'test_*.py'
 echo "  Release-tool tests: PASSED"
`
		findings := rule.Check(diff)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
		}
		if findings[0].Rule != "release-preflight-scope" {
			t.Errorf("expected rule release-preflight-scope, got %s", findings[0].Rule)
		}
		if findings[0].Severity != "medium" {
			t.Errorf("expected severity medium, got %s", findings[0].Severity)
		}
	})

	t.Run("passes scoped test discovery in release preflight", func(t *testing.T) {
		diff := `diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh
--- a/scripts/quality_gate.sh
+++ b/scripts/quality_gate.sh
@@ -65,5 +65,5 @@ echo "[10/11] Verifying changelog..."
 
 echo "[11/11] Running release-tool unit tests..."
+python3 -m unittest discover -s test/scripts -p 'test_generate_release_*.py'
 echo "  Release-tool tests: PASSED"
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
		}
	})
}
