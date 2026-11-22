package review

import (
	"testing"
)

func TestMockTelemetryBleedRule(t *testing.T) {
	rule := MockTelemetryBleedRule{}

	t.Run("flags physical serial bridge initializing telemetry with const simulator default", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/hardware/physical_serial_bridge.dart b/lib/core/services/hardware/physical_serial_bridge.dart
--- a/lib/core/services/hardware/physical_serial_bridge.dart
+++ b/lib/core/services/hardware/physical_serial_bridge.dart
@@ -30,6 +30,8 @@ class PhysicalSerialBridge {
+  PinTelemetry _telemetry = const PinTelemetry();
+  HardwareConnectionState _state = HardwareConnectionState.disconnected;
`
		findings := rule.Check(diff)
		if len(findings) < 1 {
			t.Fatalf("expected at least 1 finding, got %d: %+v", len(findings), findings)
		}
		if findings[0].Rule != "mock-telemetry-bleed" {
			t.Errorf("expected rule mock-telemetry-bleed, got %s", findings[0].Rule)
		}
	})

	t.Run("passes when physical serial bridge initializes with physicalEmpty factory", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/hardware/physical_serial_bridge.dart b/lib/core/services/hardware/physical_serial_bridge.dart
--- a/lib/core/services/hardware/physical_serial_bridge.dart
+++ b/lib/core/services/hardware/physical_serial_bridge.dart
@@ -30,6 +30,8 @@ class PhysicalSerialBridge {
+  PinTelemetry _telemetry = PinTelemetry.physicalEmpty();
+  HardwareConnectionState _state = HardwareConnectionState.disconnected;
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
		}
	})
}
