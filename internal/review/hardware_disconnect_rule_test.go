package review

import (
	"testing"
)

func TestHardwareDisconnectRule(t *testing.T) {
	rule := HardwareDisconnectRule{}

	t.Run("flags disconnect closing connection without wire safe state command", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/hardware/physical_serial_bridge.dart b/lib/core/services/hardware/physical_serial_bridge.dart
--- a/lib/core/services/hardware/physical_serial_bridge.dart
+++ b/lib/core/services/hardware/physical_serial_bridge.dart
@@ -265,10 +265,12 @@ class PhysicalSerialBridge {
+  Future<void> disconnect() async {
+    _safetyInterlock?.enterSafeState();
+    await _closeConnection();
+    _transitionTo(HardwareConnectionState.disconnected);
+  }
`
		findings := rule.Check(diff)
		if len(findings) < 1 {
			t.Fatalf("expected at least 1 finding, got %d: %+v", len(findings), findings)
		}
		if findings[0].Rule != "hardware-disconnect-safe-state" {
			t.Errorf("expected rule hardware-disconnect-safe-state, got %s", findings[0].Rule)
		}
	})

	t.Run("passes when disconnect sends safe state command before closing", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/hardware/physical_serial_bridge.dart b/lib/core/services/hardware/physical_serial_bridge.dart
--- a/lib/core/services/hardware/physical_serial_bridge.dart
+++ b/lib/core/services/hardware/physical_serial_bridge.dart
@@ -265,10 +265,13 @@ class PhysicalSerialBridge {
+  Future<void> disconnect() async {
+    await writeLine('SAFE_STATE');
+    _safetyInterlock?.enterSafeState();
+    await _closeConnection();
+    _transitionTo(HardwareConnectionState.disconnected);
+  }
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
		}
	})
}
