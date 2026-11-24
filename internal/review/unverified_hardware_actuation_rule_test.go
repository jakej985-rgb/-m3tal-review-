package review

import (
	"testing"
)

func TestUnverifiedHardwareActuationRule(t *testing.T) {
	rule := UnverifiedHardwareActuationRule{}

	t.Run("flags assumed stop confirmation on wire write", func(t *testing.T) {
		diff := `diff --git a/lib/physical_serial_bridge.dart b/lib/physical_serial_bridge.dart
--- a/lib/physical_serial_bridge.dart
+++ b/lib/physical_serial_bridge.dart
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

	t.Run("flags write-only stop command without ACK verification", func(t *testing.T) {
		diff := `diff --git a/lib/physical_serial_bridge.dart b/lib/physical_serial_bridge.dart
--- a/lib/physical_serial_bridge.dart
+++ b/lib/physical_serial_bridge.dart
@@ -525,5 +525,5 @@
+    final ack = await bridge.sendStopCommand();
+    _publishTelemetry(_telemetry.copyWith(stopConfirmed: true));
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding when sendStopCommand is called without checking ack, got 0")
		}
	})

	t.Run("flags stop confirmation when ack appears only in comments", func(t *testing.T) {
		diff := `diff --git a/lib/physical_serial_bridge.dart b/lib/physical_serial_bridge.dart
--- a/lib/physical_serial_bridge.dart
+++ b/lib/physical_serial_bridge.dart
@@ -525,5 +525,5 @@
+    // ACK: received from peripheral
+    _publishTelemetry(_telemetry.copyWith(stopConfirmed: true));
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding when ACK appears only in comment, got 0")
		}
	})

	t.Run("flags stop confirmation outside the ack-checking branch", func(t *testing.T) {
		diff := `diff --git a/lib/physical_serial_bridge.dart b/lib/physical_serial_bridge.dart
--- a/lib/physical_serial_bridge.dart
+++ b/lib/physical_serial_bridge.dart
@@ -525,8 +525,8 @@
+    if (ack.isSuccess) {
+      _log('ack confirmed');
+    }
+    _publishTelemetry(_telemetry.copyWith(stopConfirmed: true));
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding when stop confirmation is outside the ACK branch, got 0")
		}
	})

	t.Run("flags stop confirmation guarded only by local telemetry check", func(t *testing.T) {
		diff := `diff --git a/lib/physical_serial_bridge.dart b/lib/physical_serial_bridge.dart
--- a/lib/physical_serial_bridge.dart
+++ b/lib/physical_serial_bridge.dart
@@ -525,5 +525,5 @@
+    if (!_telemetry.stopConfirmed) {
+      _publishTelemetry(_telemetry.copyWith(stopConfirmed: true));
+    }
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for local telemetry check without ACK, got 0")
		}
	})

	t.Run("flags stop confirmation guarded by negative ACK check", func(t *testing.T) {
		diff := `diff --git a/lib/physical_serial_bridge.dart b/lib/physical_serial_bridge.dart
--- a/lib/physical_serial_bridge.dart
+++ b/lib/physical_serial_bridge.dart
@@ -525,5 +525,5 @@
+    if (reply.type != PacketType.ack) {
+      _publishTelemetry(_telemetry.copyWith(stopConfirmed: true));
+    }
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding when stop is guarded by negative ACK comparison, got 0")
		}
	})

	t.Run("flags stop confirmation under non-ACK switch cases", func(t *testing.T) {
		diff := `diff --git a/lib/physical_serial_bridge.dart b/lib/physical_serial_bridge.dart
--- a/lib/physical_serial_bridge.dart
+++ b/lib/physical_serial_bridge.dart
@@ -525,8 +525,8 @@
+    switch (reply.type) {
+      case PacketType.ack:
+        break;
+      case PacketType.error:
+        _publishTelemetry(_telemetry.copyWith(stopConfirmed: true));
+        break;
+    }
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding when stop confirmation is under case PacketType.error, got 0")
		}
	})

	t.Run("allows stop confirmation in ACK switch case", func(t *testing.T) {
		diff := `diff --git a/lib/physical_serial_bridge.dart b/lib/physical_serial_bridge.dart
--- a/lib/physical_serial_bridge.dart
+++ b/lib/physical_serial_bridge.dart
@@ -525,8 +525,8 @@
+    switch (reply.type) {
+      case PacketType.ack:
+        _publishTelemetry(_telemetry.copyWith(stopConfirmed: true));
+        break;
+      case PacketType.error:
+        break;
+    }
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for stop confirmation under case PacketType.ack, got %d", len(findings))
		}
	})

	t.Run("allows stop confirmation guarded by firmware ACK", func(t *testing.T) {
		diff := `diff --git a/lib/physical_serial_bridge.dart b/lib/physical_serial_bridge.dart
--- a/lib/physical_serial_bridge.dart
+++ b/lib/physical_serial_bridge.dart
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

	t.Run("allows stop confirmation in nested block inside ACK branch", func(t *testing.T) {
		diff := `diff --git a/lib/physical_serial_bridge.dart b/lib/physical_serial_bridge.dart
--- a/lib/physical_serial_bridge.dart
+++ b/lib/physical_serial_bridge.dart
@@ -525,8 +525,8 @@
+    if (ack.isSuccess) {
+      logAck();
+      if (mounted) {
+        _publishTelemetry(_telemetry.copyWith(stopConfirmed: true));
+      }
+    }
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for stop confirmation nested inside ACK branch, got %d", len(findings))
		}
	})

	t.Run("allows stop confirmation in else-if ACK branch", func(t *testing.T) {
		diff := `diff --git a/lib/physical_serial_bridge.dart b/lib/physical_serial_bridge.dart
--- a/lib/physical_serial_bridge.dart
+++ b/lib/physical_serial_bridge.dart
@@ -525,8 +525,8 @@
+    if (isTimeout) {
+      handleTimeout();
+    } else if (ack.isSuccess) {
+      _publishTelemetry(_telemetry.copyWith(stopConfirmed: true));
+    }
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for stop confirmation in else-if ACK branch, got %d", len(findings))
		}
	})

	t.Run("flags unverified hardware output controls gated only on isConnected", func(t *testing.T) {
		diff := `diff --git a/lib/physical_serial_bridge.dart b/lib/physical_serial_bridge.dart
--- a/lib/physical_serial_bridge.dart
+++ b/lib/physical_serial_bridge.dart
@@ -300,5 +300,5 @@
+    onPressed: (isConnected) ? () {
+      bridge.send('LED:ON');
+    } : null,
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for output control gated only on isConnected, got 0")
		}
	})

	t.Run("flags hardware output controls with optional disjunctive verification", func(t *testing.T) {
		diff := `diff --git a/lib/physical_serial_bridge.dart b/lib/physical_serial_bridge.dart
--- a/lib/physical_serial_bridge.dart
+++ b/lib/physical_serial_bridge.dart
@@ -300,6 +300,6 @@
+    onPressed: (isConnected ||
+        isProtocolVerified) ? () {
+      bridge.send('LED:ON');
+    } : null,
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for optional disjunctive verification, got 0")
		}
	})

	t.Run("flags staged review with unchanged guard and newly added action", func(t *testing.T) {
		diff := `diff --git a/lib/physical_serial_bridge.dart b/lib/physical_serial_bridge.dart
--- a/lib/physical_serial_bridge.dart
+++ b/lib/physical_serial_bridge.dart
@@ -300,4 +300,5 @@
     onPressed: (isConnected) ? () {
+      bridge.send('LED:ON');
     } : null,
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding when action is added inside existing guard, got 0")
		}
	})

	t.Run("allows hardware output controls with wrapped multiline protocol verification", func(t *testing.T) {
		diff := `diff --git a/lib/physical_serial_bridge.dart b/lib/physical_serial_bridge.dart
--- a/lib/physical_serial_bridge.dart
+++ b/lib/physical_serial_bridge.dart
@@ -300,6 +300,6 @@
+    onPressed: (isConnected &&
+        isProtocolVerified) ? () {
+      bridge.send('LED:ON');
+    } : null,
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for multiline verified output control, got %d", len(findings))
		}
	})

	t.Run("handles null-aware operators and quoted braces in button callback", func(t *testing.T) {
		diff := `diff --git a/lib/physical_serial_bridge.dart b/lib/physical_serial_bridge.dart
--- a/lib/physical_serial_bridge.dart
+++ b/lib/physical_serial_bridge.dart
@@ -300,7 +300,7 @@
+    onPressed: (device?.isConnected && isProtocolVerified) ? () {
+      logger.info("status: {closed}");
+      bridge.send('LED:ON');
+    } : null,
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings when callback has quoted braces and null-aware operator, got %d", len(findings))
		}
	})

	t.Run("does not attribute hardware commands to neighboring buttons", func(t *testing.T) {
		diff := `diff --git a/lib/physical_serial_bridge.dart b/lib/physical_serial_bridge.dart
--- a/lib/physical_serial_bridge.dart
+++ b/lib/physical_serial_bridge.dart
@@ -300,10 +300,10 @@
+    IconButton(
+      icon: const Icon(Icons.refresh),
+      onPressed: isConnected ? refresh : null,
+    ),
+    IconButton(
+      icon: const Icon(Icons.power),
+      onPressed: (isConnected && isProtocolVerified) ? () {
+        bridge.send('LED:ON');
+      } : null,
+    ),
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings when refresh button precedes verified button, got %d", len(findings))
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
