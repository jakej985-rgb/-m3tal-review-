package review

import (
	"testing"
)

func TestUnparentedLauncherRule(t *testing.T) {
	rule := UnparentedLauncherRule{}

	t.Run("flags external launchUrl in child feature screen", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/features/parts/part_detail_screen.dart b/lib/presentation/features/parts/part_detail_screen.dart
--- a/lib/presentation/features/parts/part_detail_screen.dart
+++ b/lib/presentation/features/parts/part_detail_screen.dart
@@ -100,5 +100,6 @@ class PartDetailScreen {
   void _openDatasheet(String url) {
+    launchUrl(Uri.parse(url));
   }
`
		findings := rule.Check(diff)
		if len(findings) < 1 {
			t.Fatalf("expected at least 1 finding, got %d: %+v", len(findings), findings)
		}
		if findings[0].Rule != "unparented-external-launcher" {
			t.Errorf("expected rule unparented-external-launcher, got %s", findings[0].Rule)
		}
	})

	t.Run("passes when external launch is gated behind parent session verification", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/features/parts/part_detail_screen.dart b/lib/presentation/features/parts/part_detail_screen.dart
--- a/lib/presentation/features/parts/part_detail_screen.dart
+++ b/lib/presentation/features/parts/part_detail_screen.dart
@@ -100,8 +100,11 @@ class PartDetailScreen {
   void _openDatasheet(String url) async {
+    if (await ParentGateDialog.verify(context)) {
+      launchUrl(Uri.parse(url));
+    }
   }
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
		}
	})
}
