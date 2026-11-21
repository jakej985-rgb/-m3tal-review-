package review

import (
	"testing"
)

func TestHotPathRuleDetectsRegExpInBuild(t *testing.T) {
	diff := `diff --git a/lib/widgets/user_view.dart b/lib/widgets/user_view.dart
new file mode 100644
--- /dev/null
+++ b/lib/widgets/user_view.dart
@@ -0,0 +1,12 @@
+class UserView extends StatelessWidget {
+  @override
+  Widget build(BuildContext context) {
+    final regex = RegExp(r'^[a-z0-9]+$');
+    if (regex.hasMatch(username)) {
+      return Text('Valid');
+    }
+    return Text('Invalid');
+  }
+}
+`

	rule := HotPathRule{}
	findings := rule.Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Rule != "hot-path-allocation" {
		t.Errorf("expected rule hot-path-allocation, got %s", f.Rule)
	}
	if f.Line != 4 {
		t.Errorf("expected line 4, got %d", f.Line)
	}
}

func TestHotPathRuleDetectsSortInBuild(t *testing.T) {
	diff := `diff --git a/lib/widgets/user_list.dart b/lib/widgets/user_list.dart
new file mode 100644
--- /dev/null
+++ b/lib/widgets/user_list.dart
@@ -0,0 +1,11 @@
+class UserList extends StatelessWidget {
+  @override
+  Widget build(BuildContext context) {
+    final items = widget.items;
+    items.sort((a, b) => a.name.compareTo(b.name));
+    return ListView.builder(
+      itemBuilder: (ctx, i) => Text(items[i].name),
+    );
+  }
+}
+`

	rule := HotPathRule{}
	findings := rule.Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Rule != "hot-path-allocation" {
		t.Errorf("expected rule hot-path-allocation, got %s", f.Rule)
	}
	if f.Line != 5 {
		t.Errorf("expected line 5, got %d", f.Line)
	}
}

func TestHotPathRuleAllowsStaticRegExp(t *testing.T) {
	diff := `diff --git a/lib/widgets/user_view.dart b/lib/widgets/user_view.dart
new file mode 100644
--- /dev/null
+++ b/lib/widgets/user_view.dart
@@ -0,0 +1,14 @@
+class UserView extends StatelessWidget {
+  static final regex = RegExp(r'^[a-z0-9]+$');
+
+  @override
+  Widget build(BuildContext context) {
+    if (regex.hasMatch(username)) {
+      return Text('Valid');
+    }
+    return Text('Invalid');
+  }
+}
+`

	rule := HotPathRule{}
	findings := rule.Check(diff)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}
