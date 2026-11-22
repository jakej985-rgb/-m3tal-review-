package review

import (
	"testing"
)

func TestCIOrphanedTestsRule(t *testing.T) {
	rule := CIOrphanedTestsRule{}

	t.Run("flags narrowed discover pattern when no sibling test step runs remaining suites", func(t *testing.T) {
		diff := `diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -70,5 +70,6 @@ jobs:
       - name: Run release-tool unit tests
+        run: python3 -m unittest discover -s test/scripts -p 'test_generate_release_*.py'
`
		findings := rule.Check(diff)
		if len(findings) < 1 {
			t.Fatalf("expected at least 1 finding, got %d: %+v", len(findings), findings)
		}
		if findings[0].Rule != "ci-orphaned-test-suite" {
			t.Errorf("expected rule ci-orphaned-test-suite, got %s", findings[0].Rule)
		}
	})

	t.Run("passes when workflow includes sibling step running remaining suites", func(t *testing.T) {
		diff := `diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -70,8 +70,11 @@ jobs:
       - name: Run release-tool unit tests
+        run: python3 -m unittest discover -s test/scripts -p 'test_generate_release_*.py'
+
+      - name: Run lesson-tool unit tests
+        run: python3 -m unittest discover -s test/scripts -p 'test_*lesson*.py'
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
		}
	})
}
