package review

import (
	"strings"
	"testing"
)

func TestStaleStateRuleDetectsUnresetCursor(t *testing.T) {
	diff := `diff --git a/lib/presentation/lesson_detail_screen.dart b/lib/presentation/lesson_detail_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/lesson_detail_screen.dart
@@ -0,0 +1,30 @@
+class _LessonDetailScreenState extends State<LessonDetailScreen> {
+  int _currentStepIndex = 0;
+  late Future<Lesson> _lessonFuture;
+
+  @override
+  void initState() {
+    super.initState();
+    _lessonFuture = repo.getLessonById(widget.lessonId);
+  }
+
+  @override
+  void didUpdateWidget(covariant LessonDetailScreen oldWidget) {
+    super.didUpdateWidget(oldWidget);
+    if (oldWidget.lessonId != widget.lessonId) {
+      _lessonFuture = repo.getLessonById(widget.lessonId);
+    }
+  }
+
+  @override
+  Widget build(BuildContext context) {
+    return FutureBuilder<Lesson>(
+      future: _lessonFuture,
+      builder: (context, snapshot) {
+        final lesson = snapshot.data!;
+        final currentStep = lesson.steps[_currentStepIndex];
+        return Text(currentStep.title);
+      },
+    );
+  }
+}
`
	rule := StaleStateRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.Rule != "stale-state-invalidation" {
		t.Errorf("expected rule stale-state-invalidation, got %s", f.Rule)
	}
	if !strings.Contains(f.Message, "_currentStepIndex") {
		t.Errorf("expected cursor in message, got %s", f.Message)
	}
	if !strings.Contains(f.Message, "RangeError") {
		t.Errorf("expected RangeError in message, got %s", f.Message)
	}
}

func TestStaleStateRuleAllowsResetCursor(t *testing.T) {
	diff := `diff --git a/lib/presentation/lesson_detail_screen.dart b/lib/presentation/lesson_detail_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/lesson_detail_screen.dart
@@ -0,0 +1,31 @@
+class _LessonDetailScreenState extends State<LessonDetailScreen> {
+  int _currentStepIndex = 0;
+  late Future<Lesson> _lessonFuture;
+
+  @override
+  void didUpdateWidget(covariant LessonDetailScreen oldWidget) {
+    super.didUpdateWidget(oldWidget);
+    if (oldWidget.lessonId != widget.lessonId) {
+      _lessonFuture = repo.getLessonById(widget.lessonId);
+      _currentStepIndex = 0;
+    }
+  }
+
+  @override
+  Widget build(BuildContext context) {
+    return FutureBuilder<Lesson>(
+      future: _lessonFuture,
+      builder: (context, snapshot) {
+        final lesson = snapshot.data!;
+        final currentStep = lesson.steps[_currentStepIndex];
+        return Text(currentStep.title);
+      },
+    );
+  }
+}
`
	rule := StaleStateRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when cursor is reset, got %d: %+v", len(findings), findings)
	}
}

func TestStaleStateRuleDetectsUntestedCacheBranch(t *testing.T) {
	diff := `diff --git a/test/widget/lesson_detail_fetch_efficiency_test.dart b/test/widget/lesson_detail_fetch_efficiency_test.dart
new file mode 100644
--- /dev/null
+++ b/test/widget/lesson_detail_fetch_efficiency_test.dart
@@ -0,0 +1,18 @@
+void main() {
+  testWidgets('LessonDetailScreen fetches the lesson once across rebuilds', (tester) async {
+    await tester.pumpWidget(
+      const MaterialApp(
+        home: LessonDetailScreen(lessonId: 'l01_01'),
+      ),
+    );
+    await tester.pumpAndSettle();
+  });
+}
`
	rule := StaleStateRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for untested cache branch, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if !strings.Contains(f.Message, "didUpdateWidget") {
		t.Errorf("expected didUpdateWidget in message, got %s", f.Message)
	}
}
