package review

import (
	"testing"
)

func TestUnboundedBufferRule(t *testing.T) {
	rule := UnboundedBufferRule{}

	t.Run("flags chunk accumulator without buffer size clamp", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/hardware/web_serial_transport_web.dart b/lib/core/services/hardware/web_serial_transport_web.dart
--- a/lib/core/services/hardware/web_serial_transport_web.dart
+++ b/lib/core/services/hardware/web_serial_transport_web.dart
@@ -200,8 +200,10 @@ class WebSerialTransport {
   void _handleChunk(String chunk) {
+    _buffer += chunk;
+    while (_buffer.contains('\n')) {
+      final line = _buffer.substring(0, _buffer.indexOf('\n'));
+      _buffer = _buffer.substring(_buffer.indexOf('\n') + 1);
+    }
   }
`
		findings := rule.Check(diff)
		if len(findings) < 1 {
			t.Fatalf("expected at least 1 finding, got %d: %+v", len(findings), findings)
		}
		if findings[0].Rule != "unbounded-serial-buffer" {
			t.Errorf("expected rule unbounded-serial-buffer, got %s", findings[0].Rule)
		}
	})

	t.Run("passes when chunk accumulator enforces buffer clamp", func(t *testing.T) {
		diff := `diff --git a/lib/core/services/hardware/web_serial_transport_web.dart b/lib/core/services/hardware/web_serial_transport_web.dart
--- a/lib/core/services/hardware/web_serial_transport_web.dart
+++ b/lib/core/services/hardware/web_serial_transport_web.dart
@@ -200,8 +200,12 @@ class WebSerialTransport {
   void _handleChunk(String chunk) {
+    if (_buffer.length > maxBufferSize) {
+      _buffer = '';
+    }
+    _buffer += chunk;
   }
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
		}
	})
}
