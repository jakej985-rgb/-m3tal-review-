package review

import (
	"testing"
)

func TestFlutterKeepAliveRule(t *testing.T) {
	rule := FlutterKeepAliveRule{}

	t.Run("ignores scrollable owner widget building ListView", func(t *testing.T) {
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
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for scrollable owner, got %d: %+v", len(findings), findings)
		}
	})

	t.Run("flags stateful row widget in ListView omitting keepalive", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/features/terminal/terminal_row.dart b/lib/presentation/features/terminal/terminal_row.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/features/terminal/terminal_row.dart
@@ -0,0 +1,30 @@
+import 'package:flutter/material.dart';
+
+class TerminalRow extends StatefulWidget {
+  const TerminalRow({super.key});
+  @override
+  State<TerminalRow> createState() => _TerminalRowState();
+}
+
+class _TerminalRowState extends State<TerminalRow> {
+  final _commandController = TextEditingController();
+  bool _autoScroll = true;
+
+  @override
+  Widget build(BuildContext context) {
+    return TextField(controller: _commandController);
+  }
+}
+
+class TerminalScreen extends StatelessWidget {
+  @override
+  Widget build(BuildContext context) {
+    return ListView.builder(
+      itemBuilder: (context, index) => const TerminalRow(),
+    );
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding for stateful row, got %d", len(findings))
		}
		if findings[0].Rule != "flutter-listview-unpreserved-state" {
			t.Errorf("unexpected rule name: %s", findings[0].Rule)
		}
	})

	t.Run("passes when AutomaticKeepAliveClientMixin is included", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/features/terminal/terminal_row.dart b/lib/presentation/features/terminal/terminal_row.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/features/terminal/terminal_row.dart
@@ -0,0 +1,28 @@
+import 'package:flutter/material.dart';
+
+class TerminalRow extends StatefulWidget {
+  const TerminalRow({super.key});
+  @override
+  State<TerminalRow> createState() => _TerminalRowState();
+}
+
+class _TerminalRowState extends State<TerminalRow> with AutomaticKeepAliveClientMixin {
+  final _commandController = TextEditingController();
+  bool _autoScroll = true;
+
+  @override
+  bool get wantKeepAlive => true;
+
+  @override
+  Widget build(BuildContext context) {
+    super.build(context);
+    return TextField(controller: _commandController);
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("flags added interactive controller under unchanged class declaration", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/features/terminal/terminal_row.dart b/lib/presentation/features/terminal/terminal_row.dart
--- a/lib/presentation/features/terminal/terminal_row.dart
+++ b/lib/presentation/features/terminal/terminal_row.dart
@@ -1,7 +1,9 @@
 class TerminalRow extends StatefulWidget {
   const TerminalRow({super.key});
   State<TerminalRow> createState() => _TerminalRowState();
 }
 class _TerminalRowState extends State<TerminalRow> {
+  final _commandController = TextEditingController();
   Widget build(BuildContext context) {
     return TextField(controller: _commandController);
   }
 }
`
		findings := rule.Check(diff)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding when controller is added in unchanged state class, got %d", len(findings))
		}
	})
}
