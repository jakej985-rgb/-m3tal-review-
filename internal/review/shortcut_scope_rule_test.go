package review

import (
	"testing"
)

func TestShortcutScopeRule(t *testing.T) {
	rule := ShortcutScopeRule{}

	t.Run("flags CallbackShortcuts mounted inside shell scaffold", func(t *testing.T) {
		diff := `
diff --git a/lib/presentation/shared/scaffold/main_scaffold.dart b/lib/presentation/shared/scaffold/main_scaffold.dart
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/lib/presentation/shared/scaffold/main_scaffold.dart
@@ -0,0 +1,10 @@
+class MainScaffold extends StatelessWidget {
+  @override
+  Widget build(BuildContext context) {
+    return CallbackShortcuts(
+      bindings: {},
+      child: Scaffold(),
+    );
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Rule != "flutter-shell-shortcuts-ancestor" {
			t.Errorf("expected rule flutter-shell-shortcuts-ancestor, got %s", findings[0].Rule)
		}
	})

	t.Run("ignores commented out CallbackShortcuts constructors", func(t *testing.T) {
		diffCommented := `
diff --git a/lib/presentation/shared/scaffold/main_scaffold.dart b/lib/presentation/shared/scaffold/main_scaffold.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/shared/scaffold/main_scaffold.dart
@@ -0,0 +1,16 @@
+class MainScaffold extends StatelessWidget {
+  @override
+  Widget build(BuildContext context) {
+    // return CallbackShortcuts(bindings: {}, child: Scaffold());
+    /*
+    return CallbackShortcuts(
+      bindings: {},
+      child: Scaffold(),
+    );
+    */
+    return Scaffold();
+  }
+}
+`
		findings := rule.Check(diffCommented)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for commented out CallbackShortcuts, got %d", len(findings))
		}
	})

	t.Run("passes when CallbackShortcuts wraps root MaterialApp.router in app_shell.dart", func(t *testing.T) {
		diffRootApp := `
diff --git a/lib/presentation/app_shell.dart b/lib/presentation/app_shell.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/app_shell.dart
@@ -0,0 +1,13 @@
+class AppShell extends StatelessWidget {
+  @override
+  Widget build(BuildContext context) {
+    return CallbackShortcuts(
+      bindings: {},
+      child: MaterialApp.router(
+        routerConfig: appRouter,
+      ),
+    );
+  }
+}
+`
		findings := rule.Check(diffRootApp)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings when CallbackShortcuts wraps root MaterialApp.router, got %d", len(findings))
		}
	})
}
