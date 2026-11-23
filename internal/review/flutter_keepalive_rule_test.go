package review

import (
	"testing"
)

func TestFlutterKeepAliveRule(t *testing.T) {
	rule := FlutterKeepAliveRule{}

	t.Run("flags stateful widget with controllers in ListView omitting keepalive", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/features/terminal/serial_terminal.dart b/lib/presentation/features/terminal/serial_terminal.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/features/terminal/serial_terminal.dart
@@ -0,0 +1,25 @@
+import 'package:flutter/material.dart';
+
+class SerialTerminal extends StatefulWidget {
+  const SerialTerminal({super.key});
+  @override
+  State<SerialTerminal> createState() => _SerialTerminalState();
+}
+
+class _SerialTerminalState extends State<SerialTerminal> {
+  final _commandController = TextEditingController();
+  bool _autoScroll = true;
+
+  @override
+  Widget build(BuildContext context) {
+    return ListView(
+      children: [
+        TextField(controller: _commandController),
+      ],
+    );
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Rule != "flutter-listview-unpreserved-state" {
			t.Errorf("unexpected rule name: %s", findings[0].Rule)
		}
	})

	t.Run("passes when AutomaticKeepAliveClientMixin is included", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/features/terminal/serial_terminal.dart b/lib/presentation/features/terminal/serial_terminal.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/features/terminal/serial_terminal.dart
@@ -0,0 +1,28 @@
+import 'package:flutter/material.dart';
+
+class SerialTerminal extends StatefulWidget {
+  const SerialTerminal({super.key});
+  @override
+  State<SerialTerminal> createState() => _SerialTerminalState();
+}
+
+class _SerialTerminalState extends State<SerialTerminal> with AutomaticKeepAliveClientMixin {
+  final _commandController = TextEditingController();
+  bool _autoScroll = true;
+
+  @override
+  bool get wantKeepAlive => true;
+
+  @override
+  Widget build(BuildContext context) {
+    super.build(context);
+    return ListView(
+      children: [
+        TextField(controller: _commandController),
+      ],
+    );
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})
}
