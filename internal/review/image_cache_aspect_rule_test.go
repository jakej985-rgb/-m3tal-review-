package review

import (
	"testing"
)

func TestImageCacheAspectRule(t *testing.T) {
	rule := ImageCacheAspectRule{}

	t.Run("flags Image.asset specifying both cacheWidth and cacheHeight", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/widgets/thumbnail.dart b/lib/presentation/widgets/thumbnail.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/widgets/thumbnail.dart
@@ -0,0 +1,15 @@
+import 'package:flutter/material.dart';
+
+class ThumbnailWidget extends StatelessWidget {
+  @override
+  Widget build(BuildContext context) {
+    return Image.asset(
+      'assets/photo.png',
+      cacheWidth: 100,
+      cacheHeight: 100,
+      fit: BoxFit.contain,
+    );
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Rule != "flutter-image-cache-distortion" {
			t.Errorf("unexpected rule name: %s", findings[0].Rule)
		}
	})

	t.Run("passes when specifying only a single cache dimension", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/widgets/thumbnail.dart b/lib/presentation/widgets/thumbnail.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/widgets/thumbnail.dart
@@ -0,0 +1,14 @@
+import 'package:flutter/material.dart';
+
+class ThumbnailWidget extends StatelessWidget {
+  @override
+  Widget build(BuildContext context) {
+    return Image.asset(
+      'assets/photo.png',
+      cacheWidth: 100,
+      fit: BoxFit.contain,
+    );
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})
}
