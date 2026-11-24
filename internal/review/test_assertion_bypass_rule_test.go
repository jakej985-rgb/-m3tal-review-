package review

import (
	"testing"
)

func TestTestAssertionBypassRule(t *testing.T) {
	rule := TestAssertionBypassRule{}

	t.Run("flags conditional wrap around test action", func(t *testing.T) {
		diff := `diff --git a/test/unit/gating_test.dart b/test/unit/gating_test.dart
new file mode 100644
--- /dev/null
+++ b/test/unit/gating_test.dart
@@ -0,0 +1,10 @@
+void main() {
+  test('example gating test', () async {
+    final isGated = checkGating();
+    if (!isGated) {
+      await progressRepo.completeLesson('learner', 'l01_02', 10);
+    }
+    expect(progressRepo.totalXp, 0);
+  });
+}
+`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for conditional test action bypass, got 0")
		}
		if findings[0].Rule != "test-assertion-bypass" {
			t.Errorf("expected rule test-assertion-bypass, got %s", findings[0].Rule)
		}
	})

	t.Run("allows platform or web checks", func(t *testing.T) {
		diff := `diff --git a/test/unit/platform_test.dart b/test/unit/platform_test.dart
new file mode 100644
--- /dev/null
+++ b/test/unit/platform_test.dart
@@ -0,0 +1,9 @@
+void main() {
+  test('web test', () {
+    if (kIsWeb) {
+      expect(findWeb(), isTrue);
+    }
+  });
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings for kIsWeb check, got %d", len(findings))
		}
	})

	t.Run("passes for deletion-only diff in test file", func(t *testing.T) {
		diff := "diff --git a/test/unit/gating_test.dart b/test/unit/gating_test.dart\n" +
			"--- a/test/unit/gating_test.dart\n" +
			"+++ b/test/unit/gating_test.dart\n" +
			"@@ -1,7 +1,6 @@\n" +
			" void main() {\n" +
			"   test('example gating test', () async {\n" +
			"     final isGated = checkGating();\n" +
			"-    // remove comment\n" +
			"     " + "if (!isGated) {\n" +
			"       await progressRepo.completeLesson('learner', 'l01_02', 10);\n" +
			"     }\n"
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings for deletion-only diff, got %d", len(findings))
		}
	})
}
