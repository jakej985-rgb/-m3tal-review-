package review

import (
	"testing"
)

func TestRouteGuardSchemaRule(t *testing.T) {
	rule := RouteGuardSchemaRule{}

	t.Run("flags raw map lookup in route guard", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -70,8 +70,10 @@ final GoRouter appRouter = GoRouter(
+          final list = jsonDecode(effectiveRaw) as List;
+          hasActiveProfile = list.any(
+            (item) => (item as Map<String, dynamic>)['id'] == activeId,
+          );
`
		findings := rule.Check(diff)
		if len(findings) < 1 {
			t.Fatalf("expected at least 1 finding, got %d: %+v", len(findings), findings)
		}
		if findings[0].Rule != "route-guard-schema-mismatch" {
			t.Errorf("expected rule route-guard-schema-mismatch, got %s", findings[0].Rule)
		}
	})

	t.Run("passes when route guard validates model deserialization", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -70,8 +70,10 @@ final GoRouter appRouter = GoRouter(
+          final list = jsonDecode(effectiveRaw) as List;
+          hasActiveProfile = list.any((item) {
+            final profile = LearnerProfileModel.fromJson(item as Map<String, dynamic>);
+            return profile.id == activeId;
+          });
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
		}
	})
}
