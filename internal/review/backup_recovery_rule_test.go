package review

import (
	"testing"
)

func TestBackupRecoveryRule(t *testing.T) {
	rule := BackupRecoveryRule{}

	t.Run("flags early return on null or empty primary store without checking backup", func(t *testing.T) {
		diff := `diff --git a/lib/data/datasources/local_storage_datasource.dart b/lib/data/datasources/local_storage_datasource.dart
--- a/lib/data/datasources/local_storage_datasource.dart
+++ b/lib/data/datasources/local_storage_datasource.dart
@@ -48,15 +48,16 @@ class LocalStorageDataSource {
   List<LearnerProfileModel> getProfiles() {
     final raw = _storageService.getString(_profilesKey);
+    if (raw == null || raw.isEmpty) return [];
     try {
       final list = jsonDecode(raw) as List;
       return list.map((item) => LearnerProfileModel.fromJson(item)).toList();
     } catch (_) {
       final backupRaw = _storageService.getString(_profilesBackupKey);
       if (backupRaw != null && backupRaw.isNotEmpty) {
         return (jsonDecode(backupRaw) as List).map((i) => LearnerProfileModel.fromJson(i)).toList();
       }
       return [];
     }
   }
`
		findings := rule.Check(diff)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
		}
		if findings[0].Rule != "backup-recovery-bypass" {
			t.Errorf("expected rule backup-recovery-bypass, got %s", findings[0].Rule)
		}
		if findings[0].Severity != "high" {
			t.Errorf("expected severity high, got %s", findings[0].Severity)
		}
	})

	t.Run("passes when backup recovery is checked when primary is null or empty", func(t *testing.T) {
		diff := `diff --git a/lib/data/datasources/local_storage_datasource.dart b/lib/data/datasources/local_storage_datasource.dart
--- a/lib/data/datasources/local_storage_datasource.dart
+++ b/lib/data/datasources/local_storage_datasource.dart
@@ -48,15 +48,18 @@ class LocalStorageDataSource {
   List<LearnerProfileModel> getProfiles() {
     final raw = _storageService.getString(_profilesKey);
+    String? effectiveRaw = raw;
+    if (effectiveRaw == null || effectiveRaw.isEmpty) {
+      effectiveRaw = _storageService.getString(_profilesBackupKey);
+    }
+    if (effectiveRaw == null || effectiveRaw.isEmpty) return [];
     try {
       final list = jsonDecode(effectiveRaw) as List;
       return list.map((item) => LearnerProfileModel.fromJson(item)).toList();
     } catch (_) {
       return [];
     }
   }
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
		}
	})
}
