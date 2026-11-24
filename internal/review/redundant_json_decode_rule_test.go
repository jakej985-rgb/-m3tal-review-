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

	t.Run("flags sequential decodes across lines in same block", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -80,2 +80,4 @@
+  if (tryDecodeList(raw) == null) return false;
+  return tryDecodeList(raw)!.isNotEmpty;
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for repeated decodes across lines, got 0")
		}
	})

	t.Run("does not flag decodes in opposing ternary branches", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -80,1 +80,1 @@
+  return useNewPolicy ? newPolicy(jsonDecode(raw)) : legacyPolicy(jsonDecode(raw));
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for mutually exclusive ternary branches, got %d", len(findings))
		}
	})

	t.Run("does not flag distinct payloads in validation and lookup helpers", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -80,2 +80,4 @@
+  if (!_decodesProfiles(primaryRaw)) return false;
+  return _containsLoadableProfile(backupRaw, activeId);
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for distinct payloads, got %d", len(findings))
		}
	})

	t.Run("flags lookup-only added line when validation line is unchanged", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -80,3 +80,4 @@
   final source = _decodesProfiles(profilesRaw) ? profilesRaw : backupRaw;
+  return _containsLoadableProfile(source, activeId);
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for added lookup line with unchanged validation, got 0")
		}
		if findings[0].Line != 81 {
			t.Errorf("expected finding on line 81, got %d", findings[0].Line)
		}
	})

	t.Run("flags duplicate decode inside collection in ternary true arm", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -80,1 +80,1 @@
+  return ok ? [jsonDecode(raw), {'x': jsonDecode(raw)}] : [];
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for duplicate decodes in ternary arm, got 0")
		}
	})

	t.Run("does not flag sequential decode across fallback assignment", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -80,3 +80,3 @@
+  final a = jsonDecode(raw);
+  raw ??= backupRaw;
+  final b = jsonDecode(raw);
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for decode across fallback assignment, got %d", len(findings))
		}
	})

	t.Run("does not flag unchanged duplicate decode on base branch in diff review", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -80,3 +80,4 @@
   final a = jsonDecode(raw);
   final b = jsonDecode(raw);
+  final unrelated = true;
   return unrelated;
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for unchanged duplicate decode in context, got %d", len(findings))
		}
	})

	t.Run("does not flag mutually exclusive ternary decodes with nullable cast", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -80,1 +80,1 @@
+  return useMap ? jsonDecode(raw) as Map<String, dynamic>? : jsonDecode(raw);
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for ternary with nullable cast in first arm, got %d", len(findings))
		}
	})

	t.Run("flags sequential decode when write targets same-named property rather than local", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -80,3 +80,3 @@
+  final a = jsonDecode(raw);
+  cache.raw ??= fallback;
+  final b = jsonDecode(raw);
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for duplicate decode across member write, got 0")
		}
	})

	t.Run("does not flag untouched decodes in deletion-only diff with surviving decodes", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -10,6 +10,4 @@
-import 'unused_import.dart';
-import 'unused2.dart';
   final a = jsonDecode(raw);
   final b = jsonDecode(raw);
   return a != null;
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for surviving decodes in deletion-only diff, got %d", len(findings))
		}
	})

	t.Run("does not flag mutually exclusive ternary decodes after TypeScript cast", func(t *testing.T) {
		diff := `diff --git a/src/routes/app_router.ts b/src/routes/app_router.ts
--- a/src/routes/app_router.ts
+++ b/src/routes/app_router.ts
@@ -50,1 +50,1 @@
+  return choice as boolean ? jsonDecode(raw) : jsonDecode(raw);
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for TypeScript ternary with cast condition, got %d", len(findings))
		}
	})

	t.Run("does not flag sequential decode across this field assignment", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -80,3 +80,3 @@
+  final before = jsonDecode(raw);
+  this.raw = fallback;
+  final after = jsonDecode(raw);
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for decode across this.raw assignment, got %d", len(findings))
		}
	})

	t.Run("flags sequential decode when log string contains assignment-like text", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -80,3 +80,3 @@
+  final a = jsonDecode(raw);
+  log('raw=${raw.length}');
+  final b = jsonDecode(raw);
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for duplicate decode across string containing raw=, got 0")
		}
	})

	t.Run("flags sequential decode across this field assignment when parameter shadows field", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -80,5 +80,5 @@
+  void process(String raw) {
+    final before = jsonDecode(raw);
+    this.raw = fallback;
+    final after = jsonDecode(raw);
+  }
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for duplicate decode when parameter shadows this.raw, got 0")
		}
	})

	t.Run("does not flag opposing ternary arms with nullable cast followed by null-coalescing", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -50,1 +50,1 @@
+  return useString ? jsonDecode(raw) as String? ?? '' : jsonDecode(raw);
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for Dart ternary with cast and null-coalescing, got %d", len(findings))
		}
	})

	t.Run("does not flag sequential decode across payload assignment with preceding quoted URL", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -80,5 +80,5 @@
+  final before = jsonDecode(raw);
+  if (url.startsWith("https://")) raw = fallback;
+  final after = jsonDecode(raw);
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings when payload is assigned after quoted URL, got %d", len(findings))
		}
	})

	t.Run("flags sequential decode across field assignment when untyped JS parameter shadows field", func(t *testing.T) {
		diff := `diff --git a/web/route_loader.js b/web/route_loader.js
--- a/web/route_loader.js
+++ b/web/route_loader.js
@@ -80,5 +80,5 @@
+  load(raw) {
+    const before = JSON.parse(raw);
+    this.raw = fallback;
+    const after = JSON.parse(raw);
+  }
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for duplicate decode in untyped JS method, got 0")
		}
	})

	t.Run("does not treat sibling method parameter as in-scope local across method boundary", func(t *testing.T) {
		diff := `diff --git a/lib/core/routing/app_router.dart b/lib/core/routing/app_router.dart
--- a/lib/core/routing/app_router.dart
+++ b/lib/core/routing/app_router.dart
@@ -80,9 +80,9 @@
+  void init(String raw) {
+    this.raw = raw;
+  }
+  void reload() {
+    final before = jsonDecode(raw);
+    this.raw = '{"new":1}';
+    final after = jsonDecode(raw);
+  }
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings when mutating field in method without parameter, got %d", len(findings))
		}
	})
}
