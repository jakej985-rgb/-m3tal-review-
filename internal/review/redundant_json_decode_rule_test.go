package review

import (
	"testing"
)

func TestRedundantJsonDecodeRule(t *testing.T) {
	rule := RedundantJsonDecodeRule{}

	t.Run("flags repeated decoding in router guard helpers", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -75,4 +75,4 @@
+  final source = _decodesProfiles(profilesRaw) ? profilesRaw : backupRaw;
+  return _containsLoadableProfile(source, activeId);
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for redundant profile decoding, got 0")
		}
		if findings[0].Rule != "redundant-json-decode" {
			t.Errorf("expected rule redundant-json-decode, got %s", findings[0].Rule)
		}
	})

	t.Run("allows single decode with direct list inspection", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -75,4 +75,4 @@
+  final profiles = LearnerProfileModel.tryDecodeList(profilesRaw) ??
+      LearnerProfileModel.tryDecodeList(backupRaw);
+  return profiles != null && profiles.any((profile) => profile.id == activeId);
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for single decoded list inspection, got %d", len(findings))
		}
	})
}
