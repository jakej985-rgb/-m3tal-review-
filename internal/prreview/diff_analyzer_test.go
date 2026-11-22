package prreview

import (
	"testing"
)

func TestParseUnifiedDiff(t *testing.T) {
	diffText := `diff --git a/pkg/auth/token.go b/pkg/auth/token.go
index 1234567..89abcdef 100644
--- a/pkg/auth/token.go
+++ b/pkg/auth/token.go
@@ -10,6 +10,8 @@ package auth
 import "time"
 
 func ValidateToken(t string) bool {
+	if t == "" {
+		return false
+	}
 	return true
 }
diff --git a/README.md b/README.md
new file mode 100644
index 0000000..abcdef1
--- /dev/null
+++ b/README.md
@@ -0,0 +1,3 @@
+# Project
+
+Hello world
`

	files, err := ParseUnifiedDiff(diffText)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(files))
	}

	f1 := files[0]
	if f1.NewPath != "pkg/auth/token.go" {
		t.Errorf("expected pkg/auth/token.go, got %s", f1.NewPath)
	}
	if f1.Additions != 3 {
		t.Errorf("expected 3 additions, got %d", f1.Additions)
	}
	if f1.Deletions != 0 {
		t.Errorf("expected 0 deletions, got %d", f1.Deletions)
	}
	if len(f1.Hunks) != 1 {
		t.Fatalf("expected 1 hunk, got %d", len(f1.Hunks))
	}

	changed := f1.ChangedLines()
	if !changed[13] || !changed[14] || !changed[15] {
		t.Errorf("expected lines 13, 14, 15 to be changed, got %+v", changed)
	}

	pos13 := f1.FindPositionForLine(13)
	if pos13 <= 0 {
		t.Errorf("expected valid position for line 13, got %d", pos13)
	}

	f2 := files[1]
	if !f2.IsNew {
		t.Errorf("expected f2 to be marked as new file")
	}
	if f2.NewPath != "README.md" {
		t.Errorf("expected README.md, got %s", f2.NewPath)
	}
	if f2.Additions != 3 {
		t.Errorf("expected 3 additions, got %d", f2.Additions)
	}
}
