package review

import (
	"testing"
)

func TestLedgerReplaySnapshotRule(t *testing.T) {
	rule := LedgerReplaySnapshotRule{}

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
}
