package review

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	want := Report{
		RunID:      "test-run",
		Repository: "m3tal-review",
		Branch:     "main",
		Summary:    "Review passed. No findings.",
	}

	if err := WriteReport(path, want); err != nil {
		t.Fatalf("WriteReport() error = %v", err)
	}

	got, err := ReadReport(path)
	if err != nil {
		t.Fatalf("ReadReport() error = %v", err)
	}

	if got.RunID != want.RunID {
		t.Errorf("RunID = %q, want %q", got.RunID, want.RunID)
	}

	if got.Repository != want.Repository {
		t.Errorf("Repository = %q, want %q", got.Repository, want.Repository)
	}

	if got.Branch != want.Branch {
		t.Errorf("Branch = %q, want %q", got.Branch, want.Branch)
	}

	if got.Summary != want.Summary {
		t.Errorf("Summary = %q, want %q", got.Summary, want.Summary)
	}
}

func TestReadReportMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")

	_, err := ReadReport(path)
	if err == nil {
		t.Fatal("ReadReport() expected an error for a missing file")
	}

	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ReadReport() error = %v, want file-not-found error", err)
	}
}
