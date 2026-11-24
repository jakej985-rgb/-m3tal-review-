package review

import (
	"testing"
)

func TestLazyStreamSubscriptionRule(t *testing.T) {
	rule := LazyStreamSubscriptionRule{}

	diffMissingEager := `
diff --git a/lib/presentation/features/hardware/hardware_screen.dart b/lib/presentation/features/hardware/hardware_screen.dart
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/lib/presentation/features/hardware/hardware_screen.dart
@@ -0,0 +1,15 @@
+class _HardwareScreenState extends ConsumerState<HardwareScreen> {
+  void _onConnect() {
+    bridge.connect();
+  }
+  @override
+  Widget build(BuildContext context) {
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
}
