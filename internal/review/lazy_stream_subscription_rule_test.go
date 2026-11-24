package review

import (
	"testing"
)

func TestLazyStreamSubscriptionRule(t *testing.T) {
	rule := LazyStreamSubscriptionRule{}

	t.Run("flags connection when logs are only accessed in lazy child widget", func(t *testing.T) {
		diffMissingEager := `
diff --git a/lib/presentation/features/hardware/hardware_screen.dart b/lib/presentation/features/hardware/hardware_screen.dart
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/lib/presentation/features/hardware/hardware_screen.dart
@@ -0,0 +1,21 @@
+class _HardwareScreenState extends ConsumerState<HardwareScreen> {
+  void _onConnect() {
+    bridge.connect();
+  }
+  @override
+  Widget build(BuildContext context) {
+    return LazyLogsTab();
+  }
+}
+class LazyLogsTab extends ConsumerWidget {
+  @override
+  Widget build(BuildContext context, WidgetRef ref) {
+    final logs = ref.watch(hardwareSerialLogsProvider);
+    return Container();
+  }
+}
+`
		findings := rule.Check(diffMissingEager)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Rule != "flutter-lazy-stream-listener" {
			t.Errorf("expected rule flutter-lazy-stream-listener, got %s", findings[0].Rule)
		}
	})

	t.Run("passes when eager read exists in initState", func(t *testing.T) {
		diffWithEager := `
diff --git a/lib/presentation/features/hardware/hardware_screen.dart b/lib/presentation/features/hardware/hardware_screen.dart
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/lib/presentation/features/hardware/hardware_screen.dart
@@ -0,0 +1,19 @@
+class _HardwareScreenState extends ConsumerState<HardwareScreen> {
+  @override
+  void initState() {
+    super.initState();
+    ref.read(hardwareSerialLogsProvider);
+  }
+  void _onConnect() {
+    bridge.connect();
+  }
+  @override
+  Widget build(BuildContext context) {
+    return Container();
+  }
+}
+`
		findingsWithEager := rule.Check(diffWithEager)
		if len(findingsWithEager) != 0 {
			t.Fatalf("expected 0 findings when eager read exists in initState, got %d", len(findingsWithEager))
		}
	})

	t.Run("flags connection when provider read occurs in later method after connect", func(t *testing.T) {
		diffLateRead := `
diff --git a/lib/presentation/features/hardware/hardware_screen.dart b/lib/presentation/features/hardware/hardware_screen.dart
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/lib/presentation/features/hardware/hardware_screen.dart
@@ -0,0 +1,18 @@
+class _HardwareScreenState extends ConsumerState<HardwareScreen> {
+  @override
+  void initState() {
+    super.initState();
+  }
+  void _onConnect() {
+    bridge.connect();
+    ref.read(hardwareSerialLogsProvider);
+  }
+  @override
+  Widget build(BuildContext context) {
+    return Container();
+  }
+}
+`
		findings := rule.Check(diffLateRead)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding for late provider read in connect handler, got %d", len(findings))
		}
	})

	t.Run("passes when screen unconditionally watches logs in build", func(t *testing.T) {
		diffScreenWatch := `
diff --git a/lib/presentation/features/hardware/hardware_screen.dart b/lib/presentation/features/hardware/hardware_screen.dart
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/lib/presentation/features/hardware/hardware_screen.dart
@@ -0,0 +1,16 @@
+class _HardwareScreenState extends ConsumerState<HardwareScreen> {
+  void _onConnect() {
+    bridge.connect();
+  }
+  @override
+  Widget build(BuildContext context) {
+    final logs = ref.watch(hardwareSerialLogsProvider);
+    return ElevatedButton(onPressed: _onConnect, child: Text('Connect'));
+  }
+}
+`
		findings := rule.Check(diffScreenWatch)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings when screen unconditionally watches logs in build, got %d: %+v", len(findings), findings)
		}
	})
}
