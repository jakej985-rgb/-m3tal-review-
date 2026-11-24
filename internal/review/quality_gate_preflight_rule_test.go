package review

import (
	"testing"
)

func TestQualityGatePreflightRule(t *testing.T) {
	rule := QualityGatePreflightRule{}

	t.Run("flags gate script missing preflight check", func(t *testing.T) {
		diff := `diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh
new file mode 100755
--- /dev/null
+++ b/scripts/quality_gate.sh
@@ -0,0 +1,6 @@
+#!/usr/bin/env bash
+set -e
+echo "Running tests..."
+python3 -m unittest discover -s test/scripts -p 'test_*.py'
+echo "Done"
+`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for missing preflight check, got 0")
		}
		if findings[0].Rule != "quality-gate-preflight-dependency" {
			t.Errorf("expected rule quality-gate-preflight-dependency, got %s", findings[0].Rule)
		}
	})

	t.Run("passes when preflight check exists", func(t *testing.T) {
		diff := `diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh
new file mode 100755
--- /dev/null
+++ b/scripts/quality_gate.sh
@@ -0,0 +1,8 @@
+#!/usr/bin/env bash
+set -e
+python3 -c "import yaml, jsonschema, PIL, markdown"
+echo "Running tests..."
+python3 -m unittest discover -s test/scripts -p 'test_*.py'
+echo "Done"
+`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})
}
