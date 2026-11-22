package review

import (
	"testing"
)

func TestUncanceledStreamRule(t *testing.T) {
	rule := UncanceledStreamRule{}

	t.Run("flags StreamSubscription set to null without cancel()", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/hardware/physical_serial_bridge.dart b/lib/core/services/hardware/physical_serial_bridge.dart
--- a/lib/core/services/hardware/physical_serial_bridge.dart
+++ b/lib/core/services/hardware/physical_serial_bridge.dart
@@ -435,8 +435,10 @@ class PhysicalSerialBridge {
   Future<void> _closeConnection() async {
+    _lineSubscription = null;
+    await _disconnectSubscription?.cancel();
+    _disconnectSubscription = null;
   }
`
		findings := rule.Check(diff)
		if len(findings) < 1 {
			t.Fatalf("expected at least 1 finding, got %d: %+v", len(findings), findings)
		}
		if findings[0].Rule != "uncanceled-stream-subscription" {
			t.Errorf("expected rule uncanceled-stream-subscription, got %s", findings[0].Rule)
		}
	})

	t.Run("passes when subscription is cancelled before set to null", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/hardware/physical_serial_bridge.dart b/lib/core/services/hardware/physical_serial_bridge.dart
--- a/lib/core/services/hardware/physical_serial_bridge.dart
+++ b/lib/core/services/hardware/physical_serial_bridge.dart
@@ -435,8 +435,10 @@ class PhysicalSerialBridge {
   Future<void> _closeConnection() async {
+    await _lineSubscription?.cancel();
+    _lineSubscription = null;
   }
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
		}
	})
}
