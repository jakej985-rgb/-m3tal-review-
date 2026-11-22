package review

import (
	"strings"
	"testing"
)

func TestAsyncGapRuleDetectsUnguardedSetState(t *testing.T) {
	diff := `diff --git a/lib/presentation/fetch_screen.dart b/lib/presentation/fetch_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/fetch_screen.dart
@@ -0,0 +1,15 @@
+class _FetchScreenState extends State<FetchScreen> {
+  bool _loading = false;
+
+  Future<void> _loadData() async {
+    await api.fetchData();
+    setState(() {
+      _loading = false;
+    });
+  }
+
+  @override
+  Widget build(BuildContext context) => Container();
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unguarded setState, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.Rule != "unmounted-async-gap" {
		t.Errorf("expected rule unmounted-async-gap, got %s", f.Rule)
	}
	if !strings.Contains(f.Message, "setState()") {
		t.Errorf("expected setState() in message, got %s", f.Message)
	}
	if !strings.Contains(f.Message, "without checking if (!mounted)") {
		t.Errorf("expected mounted check in message, got %s", f.Message)
	}
}

func TestAsyncGapRuleDetectsUnguardedContextUse(t *testing.T) {
	diff := `diff --git a/lib/presentation/nav_screen.dart b/lib/presentation/nav_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/nav_screen.dart
@@ -0,0 +1,12 @@
+class _NavScreenState extends State<NavScreen> {
+  Future<void> _handleSave() async {
+    await api.save();
+    Navigator.of(context).pop();
+  }
+
+  @override
+  Widget build(BuildContext context) => Container();
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unguarded Navigator.of, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if !strings.Contains(f.Message, "Navigator.of") {
		t.Errorf("expected Navigator.of in message, got %s", f.Message)
	}
}

func TestAsyncGapRuleAllowsGuardedAsync(t *testing.T) {
	diff := `diff --git a/lib/presentation/safe_screen.dart b/lib/presentation/safe_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/safe_screen.dart
@@ -0,0 +1,24 @@
+class _SafeScreenState extends State<SafeScreen> {
+  bool _loading = false;
+
+  Future<void> _loadData() async {
+    await api.fetchData();
+    if (!mounted) return;
+    setState(() {
+      _loading = false;
+    });
+  }
+
+  Future<void> _saveData() async {
+    await api.save();
+    if (context.mounted) {
+      Navigator.of(context).pop();
+    }
+  }
+
+  @override
+  Widget build(BuildContext context) => Container();
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when mounted guards are present, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRuleAllowsMultiLineAwaitWithInnerCallbacks(t *testing.T) {
	diff := `diff --git a/lib/presentation/dialog_screen.dart b/lib/presentation/dialog_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/dialog_screen.dart
@@ -0,0 +1,22 @@
+class _DialogScreenState extends State<DialogScreen> {
+  Future<void> _showConfirmation(BuildContext context) async {
+    final confirmed = await showDialog<bool>(
+      context: context,
+      builder: (dialogCtx) => Dialog(
+        child: TextButton(
+          onPressed: () => Navigator.of(dialogCtx).pop(true),
+          child: Text('OK'),
+        ),
+      ),
+    );
+    if (confirmed != true || !context.mounted) return;
+    Navigator.of(context).pop();
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for multi-line await with inner callbacks, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRuleDetectsSetStateInInitStateAndDispose(t *testing.T) {
	diff := `diff --git a/lib/presentation/screen.dart b/lib/presentation/screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/screen.dart
@@ -0,0 +1,18 @@
+class _ScreenState extends State<Screen> {
+  @override
+  void initState() {
+    super.initState();
+    setState(() {
+      _loaded = true;
+    });
+  }
+
+  @override
+  void dispose() {
+    setState(() {
+      _active = false;
+    });
+    super.dispose();
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for setState in initState and dispose, got %d: %+v", len(findings), findings)
	}
}

