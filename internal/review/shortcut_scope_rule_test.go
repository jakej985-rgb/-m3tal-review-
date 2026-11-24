package review

import (
	"testing"
)

func TestShortcutScopeRule(t *testing.T) {
	rule := ShortcutScopeRule{}

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
}
