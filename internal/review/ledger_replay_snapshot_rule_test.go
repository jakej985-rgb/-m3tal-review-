package review

import (
	"testing"
)

func TestLedgerReplaySnapshotRule(t *testing.T) {
	rule := LedgerReplaySnapshotRule{}

	t.Run("flags replay method without snapshot in bounded ledger model", func(t *testing.T) {
		diffWithoutSnapshot := `
diff --git a/lib/domain/models/progress_model.dart b/lib/domain/models/progress_model.dart
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/lib/domain/models/progress_model.dart
@@ -0,0 +1,15 @@
+class ProgressModel {
+  static const int maxLedgerEvents = 500;
+
+  static ProgressModel replayFromEvents({
+    required String learnerId,
+    required List<Event> events,
+  }) {
+    var current = ProgressModel.empty(learnerId);
+    return current;
+  }
+}
+`
		findings := rule.Check(diffWithoutSnapshot)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Rule != "event-ledger-snapshot-truncation" {
			t.Errorf("expected rule event-ledger-snapshot-truncation, got %s", findings[0].Rule)
		}
	})

	t.Run("passes when baseSnapshot is accepted", func(t *testing.T) {
		diffWithSnapshot := `
diff --git a/lib/domain/models/progress_model.dart b/lib/domain/models/progress_model.dart
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/lib/domain/models/progress_model.dart
@@ -0,0 +1,16 @@
+class ProgressModel {
+  static const int maxLedgerEvents = 500;
+
+  static ProgressModel replayFromEvents({
+    required String learnerId,
+    required List<Event> events,
+    ProgressModel? baseSnapshot,
+  }) {
+    var current = baseSnapshot ?? ProgressModel.empty(learnerId);
+    return current;
+  }
+}
+`
		findingsWithSnapshot := rule.Check(diffWithSnapshot)
		if len(findingsWithSnapshot) != 0 {
			t.Fatalf("expected 0 findings when baseSnapshot is accepted, got %d", len(findingsWithSnapshot))
		}
	})

	t.Run("passes when baseSnapshot appears on sixth line of formatted declaration", func(t *testing.T) {
		diffMultiline := `
diff --git a/lib/domain/models/progress_model.dart b/lib/domain/models/progress_model.dart
new file mode 100644
--- /dev/null
+++ b/lib/domain/models/progress_model.dart
@@ -0,0 +1,20 @@
+class ProgressModel {
+  static const int maxLedgerEvents = 500;
+
+  static ProgressModel replayFromEvents({
+    required String learnerId,
+    required String courseId,
+    required String cohortId,
+    required List<Event> events,
+    bool strict = true,
+    ProgressModel? baseSnapshot,
+  }) {
+    return ProgressModel.empty(learnerId);
+  }
+}
+`
		findings := rule.Check(diffMultiline)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings when baseSnapshot is on sixth line of signature, got %d", len(findings))
		}
	})

	t.Run("ignores replay calls in restore paths", func(t *testing.T) {
		diffCallOnly := `
diff --git a/lib/domain/models/restore_service.dart b/lib/domain/models/restore_service.dart
new file mode 100644
--- /dev/null
+++ b/lib/domain/models/restore_service.dart
@@ -0,0 +1,15 @@
+class RestoreService {
+  static const int maxLedgerEvents = 500;
+
+  Future<void> restore(List<Event> fullHistory) async {
+    final model = ProgressModel.replayFromEvents(
+      learnerId: '123',
+      events: fullHistory,
+    );
+  }
+}
+`
		findings := rule.Check(diffCallOnly)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for replay call in restore path, got %d", len(findings))
		}
	})

	t.Run("flags added eviction logic when replay method is unchanged context", func(t *testing.T) {
		diffEvictionAdded := `
diff --git a/lib/domain/models/progress_model.dart b/lib/domain/models/progress_model.dart
--- a/lib/domain/models/progress_model.dart
+++ b/lib/domain/models/progress_model.dart
@@ -1,6 +1,8 @@
 class ProgressModel {
+  static const int maxLedgerEvents = 500;
+  void evictOldEvents() {}
   static ProgressModel replayFromEvents({
     required String learnerId,
     required List<Event> events,
   }) {
     return ProgressModel.empty(learnerId);
   }
 }
`
		findings := rule.Check(diffEvictionAdded)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding when eviction logic is added to existing replay model, got %d", len(findings))
		}
	})
}
