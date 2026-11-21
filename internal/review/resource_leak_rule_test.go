package review

import (
	"strings"
	"testing"
)

func TestResourceLeakRuleDetectsUndisposedController(t *testing.T) {
	diff := `diff --git a/lib/presentation/search_screen.dart b/lib/presentation/search_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/search_screen.dart
@@ -0,0 +1,18 @@
+class _SearchScreenState extends State<SearchScreen> {
+  final TextEditingController _searchController = TextEditingController();
+  final ScrollController _scrollController = ScrollController();
+
+  @override
+  void dispose() {
+    _searchController.dispose();
+    super.dispose();
+  }
+
+  @override
+  Widget build(BuildContext context) {
+    return Container();
+  }
+}
+`
	rule := ResourceLeakRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for undisposed _scrollController, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.Rule != "resource-leak-disposable" {
		t.Errorf("expected rule resource-leak-disposable, got %s", f.Rule)
	}
	if !strings.Contains(f.Message, "_scrollController") {
		t.Errorf("expected _scrollController in message, got %s", f.Message)
	}
	if !strings.Contains(f.Message, "ScrollController") {
		t.Errorf("expected ScrollController in message, got %s", f.Message)
	}
}

func TestResourceLeakRuleAllowsProperlyDisposedState(t *testing.T) {
	diff := `diff --git a/lib/presentation/search_screen.dart b/lib/presentation/search_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/search_screen.dart
@@ -0,0 +1,19 @@
+class _SearchScreenState extends State<SearchScreen> {
+  final TextEditingController _searchController = TextEditingController();
+  final ScrollController _scrollController = ScrollController();
+
+  @override
+  void dispose() {
+    _searchController.dispose();
+    _scrollController.dispose();
+    super.dispose();
+  }
+
+  @override
+  Widget build(BuildContext context) {
+    return Container();
+  }
+}
+`
	rule := ResourceLeakRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when all controllers disposed, got %d: %+v", len(findings), findings)
	}
}

func TestResourceLeakRuleDetectsUndisposedTimer(t *testing.T) {
	diff := `diff --git a/lib/presentation/timer_screen.dart b/lib/presentation/timer_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/timer_screen.dart
@@ -0,0 +1,15 @@
+class _TimerScreenState extends State<TimerScreen> {
+  Timer? _pollingTimer;
+
+  @override
+  void dispose() {
+    super.dispose();
+  }
+
+  @override
+  Widget build(BuildContext context) {
+    return Container();
+  }
+}
+`
	rule := ResourceLeakRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for uncancelled timer, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if !strings.Contains(f.Message, "_pollingTimer") {
		t.Errorf("expected _pollingTimer in message, got %s", f.Message)
	}
	if !strings.Contains(f.Remediation, "cancel") {
		t.Errorf("expected cancel in remediation, got %s", f.Remediation)
	}
}
