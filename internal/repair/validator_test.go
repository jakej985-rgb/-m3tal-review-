package repair

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateTargetFilePath(t *testing.T) {
	repoDir := t.TempDir()

	// Safe local files inside repo
	safeFiles := []string{
		"main.go",
		"internal/review/attestation.go",
		"pkg/sub/file.txt",
	}
	for _, f := range safeFiles {
		if err := ValidateTargetFilePath(repoDir, f); err != nil {
			t.Errorf("expected safe file %q to pass, got: %v", f, err)
		}
	}

	// Path traversal attacks & unsafe paths
	unsafePaths := []struct {
		name string
		path string
	}{
		{"empty string", ""},
		{"whitespace", "   "},
		{"dot current directory", "."},
		{"parent directory prefix", "../outside.go"},
		{"nested parent traversal", "pkg/../../outside.go"},
		{"absolute path root", "/etc/passwd"},
		{"windows backslash traversal", `..\..\windows\system32`},
		{"unclean path", "pkg/./file.go"},
	}

	for _, tc := range unsafePaths {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTargetFilePath(repoDir, tc.path)
			if err == nil {
				t.Errorf("expected unsafe path %q to fail validation, but it passed", tc.path)
			}
		})
	}
}

func TestValidateTargetFilePathSymlinkEscape(t *testing.T) {
	repoDir := t.TempDir()
	outsideDir := t.TempDir()

	secretFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("sensitive"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create symlink pointing outside repo
	symlinkPath := filepath.Join(repoDir, "symlink_outside")
	if err := os.Symlink(outsideDir, symlinkPath); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	err := ValidateTargetFilePath(repoDir, "symlink_outside/secret.txt")
	if err == nil {
		t.Fatal("expected symlink escaping repository root to be rejected, but passed")
	}
	if !strings.Contains(err.Error(), "escapes repository root") {
		t.Errorf("expected escape error message, got: %v", err)
	}
}

func TestValidatePatch(t *testing.T) {
	validPatch := `--- a/main.go
+++ b/main.go
@@ -1,2 +1,2 @@
 package main
-var x = 1
+var x = 2
`

	if err := ValidatePatch(validPatch, "main.go"); err != nil {
		t.Fatalf("expected valid patch to pass, got: %v", err)
	}

	// Malformed and malicious patches
	malformedCases := []struct {
		name         string
		patch        string
		targetFile   string
		errSubstring string
	}{
		{
			name:         "empty patch",
			patch:        "",
			targetFile:   "main.go",
			errSubstring: "empty",
		},
		{
			name: "path traversal in --- header",
			patch: `--- a/../../etc/passwd
+++ b/main.go
@@ -1,1 +1,1 @@
-foo
+bar
`,
			targetFile:   "main.go",
			errSubstring: "path traversal",
		},
		{
			name: "path traversal in +++ header",
			patch: `--- a/main.go
+++ b/../../etc/passwd
@@ -1,1 +1,1 @@
-foo
+bar
`,
			targetFile:   "main.go",
			errSubstring: "path traversal",
		},
		{
			name: "absolute path in header",
			patch: `--- /etc/passwd
+++ b/main.go
@@ -1,1 +1,1 @@
-foo
+bar
`,
			targetFile:   "main.go",
			errSubstring: "absolute path",
		},
		{
			name: "header targets different file than expected",
			patch: `--- a/other.go
+++ b/other.go
@@ -1,1 +1,1 @@
-foo
+bar
`,
			targetFile:   "main.go",
			errSubstring: "does not match expected target file",
		},
		{
			name: "missing hunks",
			patch: `--- a/main.go
+++ b/main.go
`,
			targetFile:   "main.go",
			errSubstring: "no valid @@ hunks",
		},
		{
			name: "malformed hunk header",
			patch: `--- a/main.go
+++ b/main.go
@@ invalid hunk header @@
-foo
+bar
`,
			targetFile:   "main.go",
			errSubstring: "malformed hunk header",
		},
		{
			name: "hunk line count mismatch (declared 2 old lines, only provided 1)",
			patch: `--- a/main.go
+++ b/main.go
@@ -1,2 +1,1 @@
-only_one_line
+new_line
`,
			targetFile:   "main.go",
			errSubstring: "line counts mismatch",
		},
		{
			name: "invalid hunk line prefix",
			patch: `--- a/main.go
+++ b/main.go
@@ -1,1 +1,1 @@
?invalid_prefix
`,
			targetFile:   "main.go",
			errSubstring: "unexpected line prefix",
		},
		{
			name: "out of order hunks",
			patch: `--- a/main.go
+++ b/main.go
@@ -10,1 +10,1 @@
-line10
+newLine10
@@ -5,1 +5,1 @@
-line5
+newLine5
`,
			targetFile:   "main.go",
			errSubstring: "out of order or overlaps",
		},
	}

	for _, tc := range malformedCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePatch(tc.patch, tc.targetFile)
			if err == nil {
				t.Errorf("expected malformed patch %q to fail, but it passed", tc.name)
				return
			}
			if !strings.Contains(err.Error(), tc.errSubstring) {
				t.Errorf("expected error containing %q, got: %v", tc.errSubstring, err)
			}
		})
	}

	// Valid cases with spaces, quotes, tabs, new files
	validSpecialCases := []struct {
		name       string
		patch      string
		targetFile string
	}{
		{
			name: "filename with spaces",
			patch: `--- a/path with spaces/my file.go
+++ b/path with spaces/my file.go
@@ -1,1 +1,1 @@
-old
+new
`,
			targetFile: "path with spaces/my file.go",
		},
		{
			name: "quoted header path",
			patch: `--- "a/path with spaces/my file.go"
+++ "b/path with spaces/my file.go"
@@ -1,1 +1,1 @@
-old
+new
`,
			targetFile: "path with spaces/my file.go",
		},
		{
			name:       "tab and timestamp in header",
			patch:      "--- a/main.go\t2026-01-01 00:00:00.000000000 +0000\n+++ b/main.go\t2026-01-01 00:00:00.000000000 +0000\n@@ -1,1 +1,1 @@\n-old\n+new\n",
			targetFile: "main.go",
		},
		{
			name: "newly created file from dev null",
			patch: `--- /dev/null
+++ b/new_file.go
@@ -0,0 +1,2 @@
+package main
+var x = 1
`,
			targetFile: "new_file.go",
		},
	}

	for _, tc := range validSpecialCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidatePatch(tc.patch, tc.targetFile); err != nil {
				t.Fatalf("expected valid patch %q to pass, got: %v", tc.name, err)
			}
		})
	}
}
