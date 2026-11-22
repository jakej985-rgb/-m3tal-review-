package review

import (
	"testing"
)

func TestAsymmetricStorageRule(t *testing.T) {
	rule := AsymmetricStorageRule{}

	t.Run("flags asymmetric storage check in component restriction service", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/component_restriction_service.dart b/lib/core/services/component_restriction_service.dart
--- a/lib/core/services/component_restriction_service.dart
+++ b/lib/core/services/component_restriction_service.dart
@@ -1,15 +1,35 @@
 import 'package:shared_preferences/shared_preferences.dart';
+import 'storage_service.dart';
 
 class ComponentRestrictionService {
   final SharedPreferences? _prefs;
+  final StorageService? _storage;
 
+  ComponentRestrictionService([this._prefs, this._storage]);
+
+  bool isSafetyAuthorized(String safetyKey) {
+    final stored = _prefs?.getBool(storageKey) ?? _storage?.getBool(storageKey);
+    return stored ?? false;
+  }
+
   bool isUnlocked(String componentId, String learnerId) {
     if (_prefs != null) {
       final list = _prefs.getStringList(key);
       return list != null;
     }
     return false;
   }
 }
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for asymmetric storage check, got 0")
		}
		if findings[0].Rule != "asymmetric-storage-wrapper" {
			t.Errorf("unexpected rule: %s", findings[0].Rule)
		}
	})

	t.Run("passes symmetric storage wrapper", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/component_restriction_service.dart b/lib/core/services/component_restriction_service.dart
--- a/lib/core/services/component_restriction_service.dart
+++ b/lib/core/services/component_restriction_service.dart
@@ -1,15 +1,35 @@
 import 'package:shared_preferences/shared_preferences.dart';
+import 'storage_service.dart';
 
 class ComponentRestrictionService {
   final SharedPreferences? _prefs;
+  final StorageService? _storage;
 
+  ComponentRestrictionService([this._prefs, this._storage]);
+
+  bool isSafetyAuthorized(String safetyKey) {
+    final stored = _prefs?.getBool(storageKey) ?? _storage?.getBool(storageKey);
+    return stored ?? false;
+  }
+
   bool isUnlocked(String componentId, String learnerId) {
     if (_prefs != null) {
       return _prefs.getStringList(key) != null;
+    } else if (_storage != null) {
+      return _storage.getStringList(key) != null;
     }
     return false;
   }
 }
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})
}
