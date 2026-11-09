package review

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPlatformPathNormalization(t *testing.T) {
	// Test that Windows backslashes and Unix slashes normalize consistently
	cases := []struct {
		input    string
		expected string
	}{
		{"internal\\review\\file.go", "internal/review/file.go"},
		{"internal/review/file.go", "internal/review/file.go"},
		{"a\\b\\c\\d.txt", "a/b/c/d.txt"},
		{".\\main.go", "main.go"},
		{"./main.go", "main.go"},
	}

	normalize := func(p string) string {
		return filepath.ToSlash(filepath.Clean(strings.ReplaceAll(p, "\\", "/")))
	}

	for _, tc := range cases {
		cleaned := normalize(tc.input)
		if cleaned != tc.expected {
			t.Errorf("normalize(%q) = %q, want %q", tc.input, cleaned, tc.expected)
		}
	}
}

func TestPlatformAtomicReportWrites(t *testing.T) {
	tempDir := t.TempDir()
	reportPath := filepath.Join(tempDir, "reports", "platform_test.json")

	report := NewReport("run-platform-1", tempDir, "main", "abc1234", "", "", "1.0.0", nil, nil)
	if err := WriteReport(reportPath, report); err != nil {
		t.Fatalf("WriteReport failed on %s: %v", runtime.GOOS, err)
	}

	readReport, err := ReadReport(reportPath)
	if err != nil {
		t.Fatalf("ReadReport failed on %s: %v", runtime.GOOS, err)
	}

	if readReport.RunID != "run-platform-1" {
		t.Errorf("RunID mismatch: got %q, want %q", readReport.RunID, "run-platform-1")
	}

	// Overwrite atomically with updated report
	updatedReport := NewReport("run-platform-2", tempDir, "main", "abc1234", "", "", "1.0.0", nil, nil)
	if err := WriteReport(reportPath, updatedReport); err != nil {
		t.Fatalf("atomic overwrite failed on %s: %v", runtime.GOOS, err)
	}

	readUpdated, err := ReadReport(reportPath)
	if err != nil {
		t.Fatalf("ReadReport of updated report failed on %s: %v", runtime.GOOS, err)
	}
	if readUpdated.RunID != "run-platform-2" {
		t.Errorf("RunID mismatch on overwrite: got %q, want %q", readUpdated.RunID, "run-platform-2")
	}
}

func TestPlatformDirectorySyncBehavior(t *testing.T) {
	tempDir := t.TempDir()

	// defaultSyncDir should succeed or safely handle unsupported platform behavior
	if err := defaultSyncDir(tempDir); err != nil {
		t.Errorf("defaultSyncDir returned unexpected error on %s: %v", runtime.GOOS, err)
	}
}

func TestPlatformAwareExclusions(t *testing.T) {
	exclusions := []string{
		"vendor/**",
		"testdata/*",
		"main_windows.go",
	}

	testCases := []struct {
		path     string
		excluded bool
	}{
		{"vendor/pkg/dep.go", true},
		{"vendor\\pkg\\dep.go", true},
		{"testdata/sample.json", true},
		{"testdata\\sample.json", true},
		{"main_windows.go", true},
		{"src/main_windows.go", true},
		{"src/normal.go", false},
	}

	for _, tc := range testCases {
		got := isPathExcluded(tc.path, exclusions)
		if got != tc.excluded {
			t.Errorf("isPathExcluded(%q) = %v, want %v", tc.path, got, tc.excluded)
		}
	}
}

func TestPlatformRenameRetries(t *testing.T) {
	tempDir := t.TempDir()
	src := filepath.Join(tempDir, "source.txt")
	dst := filepath.Join(tempDir, "dest.txt")

	if err := osWriteFile(src, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := defaultRename(src, dst); err != nil {
		t.Fatalf("defaultRename failed: %v", err)
	}

	data, err := osReadFile(dst)
	if err != nil || string(data) != "hello" {
		t.Fatalf("read destination failed: %v, data=%s", err, string(data))
	}
}

func osWriteFile(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(name, data, perm)
}

func osReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}
