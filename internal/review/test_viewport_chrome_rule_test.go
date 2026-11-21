package review

import (
	"strings"
	"testing"
)

func TestTestViewportChromeRuleDetectsMissingShell(t *testing.T) {
	diff := `diff --git a/test/widget/home_dashboard_layout_test.dart b/test/widget/home_dashboard_layout_test.dart
new file mode 100644
--- /dev/null
+++ b/test/widget/home_dashboard_layout_test.dart
@@ -0,0 +1,15 @@
+testWidgets('Home desktop layout', (tester) async {
+  tester.view.physicalSize = const Size(1280, 720);
+  tester.view.devicePixelRatio = 1.0;
+
+  await tester.pumpWidget(
+    ProviderScope(
+      child: const MaterialApp(home: HomeScreen()),
+    ),
+  );
+
+  expect(find.byType(HomeScreen), findsOneWidget);
+});
+`
	rule := TestViewportChromeRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.Rule != "test-viewport-chrome-contract" {
		t.Errorf("expected rule test-viewport-chrome-contract, got %s", f.Rule)
	}
	if !strings.Contains(f.Message, "1280x720") || !strings.Contains(f.Message, "HomeScreen") {
		t.Errorf("expected viewport and screen in message, got %s", f.Message)
	}
	if !strings.Contains(f.Message, "MainScaffold") {
		t.Errorf("expected shell name in message, got %s", f.Message)
	}
	if !strings.Contains(f.Message, "210 dp sidebar") {
		t.Errorf("expected 210 dp sidebar in message, got %s", f.Message)
	}
}

func TestTestViewportChromeRuleAllowsShellWrappedScreen(t *testing.T) {
	diff := `diff --git a/test/widget/home_dashboard_layout_test.dart b/test/widget/home_dashboard_layout_test.dart
new file mode 100644
--- /dev/null
+++ b/test/widget/home_dashboard_layout_test.dart
@@ -0,0 +1,15 @@
+testWidgets('Home desktop layout with scaffold', (tester) async {
+  tester.view.physicalSize = const Size(1280, 720);
+
+  await tester.pumpWidget(
+    const MaterialApp(
+      home: MainScaffold(child: HomeScreen()),
+    ),
+  );
+});
+`
	rule := TestViewportChromeRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when shell is present, got %d: %+v", len(findings), findings)
	}
}

func TestTestViewportChromeRuleAllowsMobileViewport(t *testing.T) {
	diff := `diff --git a/test/widget/mobile_test.dart b/test/widget/mobile_test.dart
new file mode 100644
--- /dev/null
+++ b/test/widget/mobile_test.dart
@@ -0,0 +1,13 @@
+testWidgets('Home mobile layout', (tester) async {
+  tester.view.physicalSize = const Size(390, 844);
+
+  await tester.pumpWidget(
+    const MaterialApp(home: HomeScreen()),
+  );
+});
+`
	rule := TestViewportChromeRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for mobile viewport, got %d: %+v", len(findings), findings)
	}
}
