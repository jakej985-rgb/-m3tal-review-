package review

import (
	"testing"
)

func TestUnhandledStreamRule(t *testing.T) {
	rule := UnhandledStreamRule{}

	t.Run("flags stream listen without onError and onDone handlers", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/hardware/physical_serial_bridge.dart b/lib/core/services/hardware/physical_serial_bridge.dart
--- a/lib/core/services/hardware/physical_serial_bridge.dart
+++ b/lib/core/services/hardware/physical_serial_bridge.dart
@@ -180,5 +180,5 @@ class PhysicalSerialBridge {
+    _lineSubscription = connection.lines.listen(_handleLine);
`
		findings := rule.Check(diff)
		if len(findings) < 1 {
			t.Fatalf("expected at least 1 finding, got %d: %+v", len(findings), findings)
		}
		if findings[0].Rule != "unhandled-stream-lifecycle" {
			t.Errorf("expected rule unhandled-stream-lifecycle, got %s", findings[0].Rule)
		}
	})

	t.Run("passes when stream listen includes onError and onDone", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/hardware/physical_serial_bridge.dart b/lib/core/services/hardware/physical_serial_bridge.dart
--- a/lib/core/services/hardware/physical_serial_bridge.dart
+++ b/lib/core/services/hardware/physical_serial_bridge.dart
@@ -180,8 +180,10 @@ class PhysicalSerialBridge {
+    _lineSubscription = connection.lines.listen(
+      _handleLine,
+      onError: (err) => _handleError(err),
+      onDone: () => _handleDone(),
+    );
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
		}
	})
}
