package review

import (
	"testing"
)

func TestUnverifiedHardwareActuationRule(t *testing.T) {
	rule := UnverifiedHardwareActuationRule{}

	t.Run("flags assumed stop confirmation on wire write", func(t *testing.T) {
		diff := `diff --git a/lib/serial_bridge.dart b/lib/serial_bridge.dart
--- a/lib/serial_bridge.dart
+++ b/lib/serial_bridge.dart
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

	t.Run("allows stop confirmation guarded by firmware ACK", func(t *testing.T) {
		diff := `diff --git a/lib/serial_bridge.dart b/lib/serial_bridge.dart
--- a/lib/serial_bridge.dart
+++ b/lib/serial_bridge.dart
@@ -525,5 +525,5 @@
+    if (ack.isSuccess) {
+      _publishTelemetry(_telemetry.copyWith(stopConfirmed: true));
+    }
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for stop confirmation guarded by ACK, got %d", len(findings))
		}
	})

	t.Run("allows stop confirmation after awaiting ACK future", func(t *testing.T) {
		diff := `diff --git a/lib/serial_bridge.dart b/lib/serial_bridge.dart
--- a/lib/serial_bridge.dart
+++ b/lib/serial_bridge.dart
@@ -525,5 +525,5 @@
+    final ack = await bridge.sendStopCommand();
+    _publishTelemetry(_telemetry.copyWith(stopConfirmed: true));
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for stop confirmation after awaiting ACK, got %d", len(findings))
		}
	})

	t.Run("flags unverified hardware output controls gated only on isConnected", func(t *testing.T) {
		diff := `diff --git a/lib/serial_bridge.dart b/lib/serial_bridge.dart
--- a/lib/serial_bridge.dart
+++ b/lib/serial_bridge.dart
@@ -300,5 +300,5 @@
+    onPressed: (isConnected) ? () {
+      bridge.send('LED:ON');
+    } : null,
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for output control gated only on isConnected, got 0")
		}
		if findings[0].Rule != "unverified-hardware-actuation" {
			t.Errorf("expected rule unverified-hardware-actuation, got %s", findings[0].Rule)
		}
	})

	t.Run("allows hardware output controls gated on isConnected and isProtocolVerified", func(t *testing.T) {
		diff := `diff --git a/lib/serial_bridge.dart b/lib/serial_bridge.dart
--- a/lib/serial_bridge.dart
+++ b/lib/serial_bridge.dart
@@ -300,5 +300,5 @@
+    onPressed: (isConnected && isProtocolVerified) ? () {
+      bridge.send('LED:ON');
+    } : null,
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for verified output control, got %d", len(findings))
		}
	})

	t.Run("ignores test files", func(t *testing.T) {
		diff := `diff --git a/test/widget/hardware_control_test.dart b/test/widget/hardware_control_test.dart
--- a/test/widget/hardware_control_test.dart
+++ b/test/widget/hardware_control_test.dart
@@ -10,3 +10,3 @@
+    _publishTelemetry(_telemetry.copyWith(stopConfirmed: true));
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for test file, got %d", len(findings))
		}
	})
}
