package review

import (
	"testing"
)

func TestUnverifiedHardwareActuationRule(t *testing.T) {
	rule := UnverifiedHardwareActuationRule{}

	t.Run("flags assumed stop confirmation on wire write", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/hardware/physical_serial_bridge.dart b/lib/core/services/hardware/physical_serial_bridge.dart
--- a/lib/core/services/hardware/physical_serial_bridge.dart
+++ b/lib/core/services/hardware/physical_serial_bridge.dart
@@ -525,3 +525,3 @@
-    _publishTelemetry(_telemetry.copyWith(stopConfirmed: false));
+    _publishTelemetry(_telemetry.copyWith(stopConfirmed: _protocolNegotiated));
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for unconfirmed stop assumed true, got 0")
		}
		if findings[0].Rule != "unverified-hardware-actuation" {
			t.Errorf("expected rule unverified-hardware-actuation, got %s", findings[0].Rule)
		}
	})
}
