package review

import (
	"testing"
)

func TestSimulationPermissionsRule(t *testing.T) {
	rule := SimulationPermissionsRule{}

	t.Run("flags host permission advice in simulation screen", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/features/hardware/hardware_companion_screen.dart b/lib/presentation/features/hardware/hardware_companion_screen.dart
--- a/lib/presentation/features/hardware/hardware_companion_screen.dart
+++ b/lib/presentation/features/hardware/hardware_companion_screen.dart
@@ -165,10 +165,12 @@ class _HardwareCompanionScreenState {
                 const Text('Hardware Companion (Simulation)'),
                 Text('Virtual Hardware Bridge'),
+                Text('To connect directly to /dev/ttyACM*, user must belong to dialout group.'),
+                Text('sudo usermod -a -G dialout $USER'),
               ],
             ),
           ),
         ],
       ),
`
		findings := rule.Check(diff)
		if len(findings) < 1 {
			t.Fatalf("expected at least 1 finding, got %d: %+v", len(findings), findings)
		}
		if findings[0].Rule != "simulation-hardware-permissions" {
			t.Errorf("expected rule simulation-hardware-permissions, got %s", findings[0].Rule)
		}
	})

	t.Run("passes when simulation screen explains simulation status without host permission commands", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/features/hardware/hardware_companion_screen.dart b/lib/presentation/features/hardware/hardware_companion_screen.dart
--- a/lib/presentation/features/hardware/hardware_companion_screen.dart
+++ b/lib/presentation/features/hardware/hardware_companion_screen.dart
@@ -165,10 +165,11 @@ class _HardwareCompanionScreenState {
                 const Text('Hardware Companion (Simulation)'),
                 Text('Virtual Hardware Bridge'),
+                Text('Hardware scanning is simulated. No host serial port permissions (dialout) required.'),
               ],
             ),
           ),
         ],
       ),
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
		}
	})
}
