package review

import (
	"reflect"
	"testing"
)

func TestParseDiffAddedFile(t *testing.T) {
	diff := `diff --git a/new.go b/new.go
new file mode 100644
index 0000000..e69de29
--- /dev/null
+++ b/new.go
@@ -0,0 +1,2 @@
+package main
+func main() {}
`
	fileDiffs := ParseDiff(diff)
	if len(fileDiffs) != 1 {
		t.Fatalf("expected 1 file diff, got %d", len(fileDiffs))
	}

	fd := fileDiffs[0]
	if fd.ChangeType != FileAdded {
		t.Errorf("ChangeType = %q, want %q", fd.ChangeType, FileAdded)
	}
	if fd.Path != "new.go" {
		t.Errorf("Path = %q, want %q", fd.Path, "new.go")
	}
	if !reflect.DeepEqual(fd.AddedLines, []int{1, 2}) {
		t.Errorf("AddedLines = %v, want [1 2]", fd.AddedLines)
	}
}

func TestParseDiffDeletedFile(t *testing.T) {
	diff := `diff --git a/old.go b/old.go
deleted file mode 100644
index e69de29..0000000
--- a/old.go
+++ /dev/null
@@ -1,2 +0,0 @@
-package main
-func main() {}
`
	fileDiffs := ParseDiff(diff)
	if len(fileDiffs) != 1 {
		t.Fatalf("expected 1 file diff, got %d", len(fileDiffs))
	}

	fd := fileDiffs[0]
	if fd.ChangeType != FileDeleted {
		t.Errorf("ChangeType = %q, want %q", fd.ChangeType, FileDeleted)
	}
	if fd.Path != "old.go" {
		t.Errorf("Path = %q, want %q (not /dev/null)", fd.Path, "old.go")
	}
	if len(fd.AddedLines) != 0 {
		t.Errorf("AddedLines = %v, want empty", fd.AddedLines)
	}
}

func TestParseDiffRenamedFile(t *testing.T) {
	diff := `diff --git a/old.go b/new.go
similarity index 100%
rename from old.go
rename to new.go
`
	fileDiffs := ParseDiff(diff)
	if len(fileDiffs) != 1 {
		t.Fatalf("expected 1 file diff, got %d", len(fileDiffs))
	}

	fd := fileDiffs[0]
	if fd.ChangeType != FileRenamed {
		t.Errorf("ChangeType = %q, want %q", fd.ChangeType, FileRenamed)
	}
	if fd.Path != "new.go" {
		t.Errorf("Path = %q, want %q", fd.Path, "new.go")
	}
	if fd.OldPath != "old.go" {
		t.Errorf("OldPath = %q, want %q", fd.OldPath, "old.go")
	}
	if len(fd.AddedLines) != 0 {
		t.Errorf("AddedLines = %v, want empty for pure rename", fd.AddedLines)
	}
}

func TestParseDiffRenamedWithModifications(t *testing.T) {
	diff := `diff --git a/old.go b/new.go
similarity index 80%
rename from old.go
rename to new.go
--- a/old.go
+++ b/new.go
@@ -1,2 +1,3 @@
 package main
+func added() {}
 func main() {}
`
	fileDiffs := ParseDiff(diff)
	if len(fileDiffs) != 1 {
		t.Fatalf("expected 1 file diff, got %d", len(fileDiffs))
	}

	fd := fileDiffs[0]
	if fd.ChangeType != FileRenamed {
		t.Errorf("ChangeType = %q, want %q", fd.ChangeType, FileRenamed)
	}
	if fd.Path != "new.go" {
		t.Errorf("Path = %q, want %q", fd.Path, "new.go")
	}
	if !reflect.DeepEqual(fd.AddedLines, []int{2}) {
		t.Errorf("AddedLines = %v, want [2]", fd.AddedLines)
	}
}

func TestParseDiffMultipleHunks(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -2,3 +2,4 @@
 package main
+import "fmt"
 func foo() {}
@@ -10,3 +11,4 @@
 func bar() {
+	fmt.Println("bar")
 }
`
	fileDiffs := ParseDiff(diff)
	if len(fileDiffs) != 1 {
		t.Fatalf("expected 1 file diff, got %d", len(fileDiffs))
	}

	fd := fileDiffs[0]
	if fd.ChangeType != FileModified {
		t.Errorf("ChangeType = %q, want %q", fd.ChangeType, FileModified)
	}
	if !reflect.DeepEqual(fd.AddedLines, []int{3, 12}) {
		t.Errorf("AddedLines = %v, want [3 12]", fd.AddedLines)
	}
}

