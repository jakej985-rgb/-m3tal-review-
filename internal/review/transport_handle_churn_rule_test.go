package review

import (
	"testing"
)

func TestTransportHandleChurnRule(t *testing.T) {
	rule := TransportHandleChurnRule{}

	t.Run("flags handles clear in discovery when counter ids are used", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/hardware/web_serial_transport_web.dart b/lib/core/services/hardware/web_serial_transport_web.dart
--- a/lib/core/services/hardware/web_serial_transport_web.dart
+++ b/lib/core/services/hardware/web_serial_transport_web.dart
@@ -80,10 +80,14 @@ class WebSerialTransport {
   Future<List<SerialPortInfo>> listPorts() async {
+    final ports = await api.getPorts();
+    _handles.clear();
+    for (final port in ports) {
+      final id = 'web-serial-${_nextId++}';
+      _handles[id] = port;
+    }
   }
`
		findings := rule.Check(diff)
		if len(findings) < 1 {
			t.Fatalf("expected at least 1 finding, got %d: %+v", len(findings), findings)
		}
		if findings[0].Rule != "transport-handle-identity-churn" {
			t.Errorf("expected rule transport-handle-identity-churn, got %s", findings[0].Rule)
		}
	})

	t.Run("passes when discovery does not wipe active handles", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/hardware/web_serial_transport_web.dart b/lib/core/services/hardware/web_serial_transport_web.dart
--- a/lib/core/services/hardware/web_serial_transport_web.dart
+++ b/lib/core/services/hardware/web_serial_transport_web.dart
@@ -80,10 +80,14 @@ class WebSerialTransport {
   Future<List<SerialPortInfo>> listPorts() async {
+    final ports = await api.getPorts();
+    final result = <SerialPortInfo>[];
+    for (final port in ports) {
+      final id = _getOrCreateStableId(port);
+      result.add(_describe(port, id));
+    }
   }
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
		}
	})
}
