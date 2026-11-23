package review

import (
	"testing"
)

func TestEventLoopStarvationRule(t *testing.T) {
	rule := EventLoopStarvationRule{}

	t.Run("flags microtask yield in loop batch processor", func(t *testing.T) {
		diff := `diff --git a/lib/data/engine/batch_processor.dart b/lib/data/engine/batch_processor.dart
new file mode 100644
--- /dev/null
+++ b/lib/data/engine/batch_processor.dart
@@ -0,0 +1,15 @@
+import 'dart:async';
+
+class BatchProcessor {
+  Future<void> processItems(List<String> items) async {
+    for (int i = 0; i < items.length; i++) {
+      if (i % 10 == 0) {
+        await Future.microtask(() {});
+      }
+    }
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Rule != "dart-microtask-frame-starvation" {
			t.Errorf("unexpected rule name: %s", findings[0].Rule)
		}
	})

	t.Run("passes when yielding via Future.delayed Duration.zero", func(t *testing.T) {
		diff := `diff --git a/lib/data/engine/batch_processor.dart b/lib/data/engine/batch_processor.dart
new file mode 100644
--- /dev/null
+++ b/lib/data/engine/batch_processor.dart
@@ -0,0 +1,15 @@
+import 'dart:async';
+
+class BatchProcessor {
+  Future<void> processItems(List<String> items) async {
+    for (int i = 0; i < items.length; i++) {
+      if (i % 10 == 0) {
+        await Future<void>.delayed(Duration.zero);
+      }
+    }
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})
}
