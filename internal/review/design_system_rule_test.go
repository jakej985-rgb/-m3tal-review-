package review

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDesignSystemRuleDetectsDisabledTextScaling(t *testing.T) {
	tmpDir := t.TempDir()
	dsDir := filepath.Join(tmpDir, "design_system")
	if err := os.MkdirAll(dsDir, 0755); err != nil {
		t.Fatal(err)
	}
	dsFile := filepath.Join(dsDir, "accessibility.md")
	content := `# Design System
## Dynamic Text Scaling
Layouts are engineered to gracefully scale up to 200% system font size.
`
	if err := os.WriteFile(dsFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	diff := `diff --git a/lib/presentation/fixed_text.dart b/lib/presentation/fixed_text.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/fixed_text.dart
@@ -0,0 +1,10 @@
+Widget buildFixedText() {
+  return MediaQuery(
+    data: MediaQueryData(
+      textScaler: TextScaler.noScaling,
+    ),
+    child: Text('Fixed'),
+  );
+}
`
	rule := DesignSystemRule{RepositoryRoot: tmpDir}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.Rule != "design-system-spec" {
		t.Errorf("expected rule design-system-spec, got %s", f.Rule)
	}
	if !strings.Contains(f.Message, "Dynamic text scaling disabled") {
		t.Errorf("expected text scaling violation in message, got %s", f.Message)
	}
	if !strings.Contains(f.Remediation, "design_system/accessibility.md:2") {
		t.Errorf("expected citation in remediation, got %s", f.Remediation)
	}
}
