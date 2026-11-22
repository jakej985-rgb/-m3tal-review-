package review

import (
	"testing"
)

func TestUnflaggedTransportRule(t *testing.T) {
	rule := UnflaggedTransportRule{}

	t.Run("flags default bridge factory instantiating real USB transport without flag", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/hardware/hardware_bridge_service.dart b/lib/core/services/hardware/hardware_bridge_service.dart
--- a/lib/core/services/hardware/hardware_bridge_service.dart
+++ b/lib/core/services/hardware/hardware_bridge_service.dart
@@ -1,7 +1,8 @@
 class HardwareBridgeService {
   static IHardwareBridge createDefaultBridge() {
+    return CompositeHardwareBridge();
   }
 }
`
		findings := rule.Check(diff)
		if len(findings) < 1 {
			t.Fatalf("expected at least 1 finding, got %d: %+v", len(findings), findings)
		}
		if findings[0].Rule != "unflagged-experimental-transport" {
			t.Errorf("expected rule unflagged-experimental-transport, got %s", findings[0].Rule)
		}
	})

	t.Run("passes when factory gates physical bridge behind feature flag", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/hardware/hardware_bridge_service.dart b/lib/core/services/hardware/hardware_bridge_service.dart
--- a/lib/core/services/hardware/hardware_bridge_service.dart
+++ b/lib/core/services/hardware/hardware_bridge_service.dart
@@ -1,7 +1,11 @@
 class HardwareBridgeService {
   static IHardwareBridge createDefaultBridge() {
+    if (config.enablePhysicalHardware) {
+      return CompositeHardwareBridge();
+    }
+    return VirtualSimulationBridge();
   }
 }
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
		}
	})
}
