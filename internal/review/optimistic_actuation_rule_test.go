package review

import (
	"testing"
)

func TestOptimisticActuationRule(t *testing.T) {
	rule := OptimisticActuationRule{}

	t.Run("flags optimistic telemetry update before wire command write", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/hardware/physical_serial_bridge.dart b/lib/core/services/hardware/physical_serial_bridge.dart
--- a/lib/core/services/hardware/physical_serial_bridge.dart
+++ b/lib/core/services/hardware/physical_serial_bridge.dart
@@ -220,10 +220,13 @@ class PhysicalSerialBridge {
     if (upper == 'EMERGENCY_STOP') {
+      _telemetry = _telemetry.copyWith(pin13Led: false);
+      _telemetryController.add(_telemetry);
+      await _write(command);
       return;
     }
`
		findings := rule.Check(diff)
		if len(findings) < 1 {
			t.Fatalf("expected at least 1 finding, got %d: %+v", len(findings), findings)
		}
		if findings[0].Rule != "optimistic-actuation-safety" {
			t.Errorf("expected rule optimistic-actuation-safety, got %s", findings[0].Rule)
		}
	})

	t.Run("flags swallowed write exceptions", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/hardware/physical_serial_bridge.dart b/lib/core/services/hardware/physical_serial_bridge.dart
--- a/lib/core/services/hardware/physical_serial_bridge.dart
+++ b/lib/core/services/hardware/physical_serial_bridge.dart
@@ -320,10 +320,14 @@ class PhysicalSerialBridge {
+  Future<void> _write(String command) async {
+    try {
+      await connection.writeLine(command);
+    } catch (failure) {
+      _logSystem('write failed');
+    }
+  }
`
		findings := rule.Check(diff)
		if len(findings) < 1 {
			t.Fatalf("expected at least 1 finding, got %d: %+v", len(findings), findings)
		}
	})
}
