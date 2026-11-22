package review

import (
	"testing"
)

func TestAmbiguousHardwareMatcherRule(t *testing.T) {
	rule := AmbiguousHardwareMatcherRule{}

	t.Run("flags first-match loop with generic bridge chips", func(t *testing.T) {
		diff := `diff --git a/lib/domain/models/hardware_board_model.dart b/lib/domain/models/hardware_board_model.dart
--- a/lib/domain/models/hardware_board_model.dart
+++ b/lib/domain/models/hardware_board_model.dart
@@ -145,10 +145,17 @@ class SupportedBoards {
   static const unoR3 = HardwareBoardModel(
     supportedVidsPids: [UsbIdentifier(0x1A86, 0x7523)], // CH340
   );
   static const esp32 = HardwareBoardModel(
     supportedVidsPids: [UsbIdentifier(0x1A86, 0x7523)], // CH340
   );
+  static HardwareBoardModel? matchUsb(int vid, int pid) {
+    for (final board in all) {
+      if (board.supportedVidsPids.any((u) => u.vendorId == vid && u.productId == pid)) {
+        return board;
+      }
+    }
+    return null;
+  }
`
		findings := rule.Check(diff)
		if len(findings) < 1 {
			t.Fatalf("expected at least 1 finding, got %d: %+v", len(findings), findings)
		}
		if findings[0].Rule != "ambiguous-hardware-matcher" {
			t.Errorf("expected rule ambiguous-hardware-matcher, got %s", findings[0].Rule)
		}
	})

	t.Run("passes when matcher handles ambiguous multi-matches", func(t *testing.T) {
		diff := `diff --git a/lib/domain/models/hardware_board_model.dart b/lib/domain/models/hardware_board_model.dart
--- a/lib/domain/models/hardware_board_model.dart
+++ b/lib/domain/models/hardware_board_model.dart
@@ -145,10 +145,17 @@ class SupportedBoards {
   static const unoR3 = HardwareBoardModel(
     supportedVidsPids: [UsbIdentifier(0x1A86, 0x7523)],
   );
+  static HardwareBoardModel? matchUsb(int vid, int pid) {
+    final matches = all.where((b) => b.supportedVidsPids.any((u) => u.vendorId == vid && u.productId == pid)).toList();
+    if (matches.length > 1) {
+      return unknownUsbSerial;
+    }
+    return matches.firstOrNull;
+  }
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
		}
	})
}
