package review

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTouchTargetRuleDetectsSmallInkWell(t *testing.T) {
	diff := `diff --git a/lib/presentation/home_screen.dart b/lib/presentation/home_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/home_screen.dart
@@ -0,0 +1,15 @@
+class QuickActionTile extends StatelessWidget {
+  @override
+  Widget build(BuildContext context) {
+    return InkWell(
+      onTap: () {},
+      child: Padding(
+        padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 7),
+        child: Row(
+          children: [
+            Icon(Icons.flash_on, size: 18),
+          ],
+        ),
+      ),
+    );
+  }
+}
`
	rule := TouchTargetRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.Rule != "touch-target-size" {
		t.Errorf("expected rule touch-target-size, got %s", f.Rule)
	}
	if !strings.Contains(f.Message, "32 dp") {
		t.Errorf("expected 32 dp in message, got %s", f.Message)
	}
	if !strings.Contains(f.Message, "18 dp") || !strings.Contains(f.Message, "14 dp") {
		t.Errorf("expected breakdown in message, got %s", f.Message)
	}
}

func TestTouchTargetRuleDetectsShrinkWrapButton(t *testing.T) {
	diff := `diff --git a/lib/presentation/achievement_card.dart b/lib/presentation/achievement_card.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/achievement_card.dart
@@ -0,0 +1,14 @@
+Widget buildAchievementLink(BuildContext context) {
+  return TextButton(
+    onPressed: () {},
+    style: TextButton.styleFrom(
+      minimumSize: Size.zero,
+      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
+      tapTargetSize: MaterialTapTargetSize.shrinkWrap,
+    ),
+    child: const Text('View all', style: TextStyle(fontSize: 12)),
+  );
+}
`
	rule := TouchTargetRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if !strings.Contains(f.Message, "16 dp") {
		t.Errorf("expected 16 dp in message, got %s", f.Message)
	}
	if !strings.Contains(f.Message, "shrinkWrap") {
		t.Errorf("expected shrinkWrap in message, got %s", f.Message)
	}
}

func TestTouchTargetRuleResolvesPrecedingVariable(t *testing.T) {
	diff := `diff --git a/lib/presentation/notification_row.dart b/lib/presentation/notification_row.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/notification_row.dart
@@ -0,0 +1,21 @@
+Widget buildNotificationRow(BuildContext context, VoidCallback onTap) {
+  final content = Padding(
+    padding: const EdgeInsets.symmetric(vertical: 4),
+    child: Row(
+      children: [
+        Container(
+          width: 32,
+          height: 32,
+          child: Icon(Icons.notifications, size: 17),
+        ),
+      ],
+    ),
+  );
+
+  return InkWell(
+    onTap: onTap,
+    child: content,
+  );
+}
`
	rule := TouchTargetRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if !strings.Contains(f.Message, "40 dp") {
		t.Errorf("expected 40 dp in message, got %s", f.Message)
	}
}

func TestTouchTargetRuleAllowsSafeWidgets(t *testing.T) {
	diff := `diff --git a/lib/presentation/safe_screen.dart b/lib/presentation/safe_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/safe_screen.dart
@@ -0,0 +1,25 @@
+Widget buildSafeButtons() {
+  return Column(
+    children: [
+      // Enforced with SizedBox 48
+      SizedBox(
+        height: 48,
+        child: InkWell(
+          onTap: () {},
+          child: Icon(Icons.add, size: 18),
+        ),
+      ),
+      // Enforced with BoxConstraints minHeight 48
+      ConstrainedBox(
+        constraints: const BoxConstraints(minHeight: 48, minWidth: 48),
+        child: InkWell(
+          onTap: () {},
+          child: Icon(Icons.settings, size: 18),
+        ),
+      ),
+    ],
+  );
+}
`
	rule := TouchTargetRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for safe widgets, got %d: %+v", len(findings), findings)
	}
}

func TestTouchTargetRuleCitesDesignSystem(t *testing.T) {
	tmpDir := t.TempDir()
	dsDir := filepath.Join(tmpDir, "design_system")
	if err := os.MkdirAll(dsDir, 0755); err != nil {
		t.Fatal(err)
	}
	dsFile := filepath.Join(dsDir, "accessibility.md")
	content := `# Design System
Line 1
Line 2
- **Absolute Minimum Target Size**: **48 × 48 dp**.
`
	if err := os.WriteFile(dsFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	diff := `diff --git a/lib/presentation/tile.dart b/lib/presentation/tile.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/tile.dart
@@ -0,0 +1,10 @@
+Widget buildTile() {
+  return InkWell(
+    onTap: () {},
+    child: Padding(
+      padding: const EdgeInsets.all(5),
+      child: Icon(Icons.home, size: 20),
+    ),
+  );
+}
`
	rule := TouchTargetRule{RepositoryRoot: tmpDir}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if !strings.Contains(f.Remediation, "design_system/accessibility.md:4") {
		t.Errorf("expected design system citation in remediation, got %s", f.Remediation)
	}
}
