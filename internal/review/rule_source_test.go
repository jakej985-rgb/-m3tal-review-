package review

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadRuleSourcePathTraversal(t *testing.T) {
	tempDir := t.TempDir()
	secretFile := filepath.Join(tempDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("sensitive-secret-token"), 0644); err != nil {
		t.Fatalf("failed to write secret file: %v", err)
	}

	repoDir := filepath.Join(tempDir, "repo")
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		t.Fatalf("failed to create repo dir: %v", err)
	}
	trackedFile := filepath.Join(repoDir, "normal.txt")
	if err := os.WriteFile(trackedFile, []byte("normal-content"), 0644); err != nil {
		t.Fatalf("failed to write normal file: %v", err)
	}

	// 1. Verify safe local path works
	content, err := readRuleSource(repoDir, "normal.txt", true)
	if err != nil {
		t.Fatalf("readRuleSource failed for safe path: %v", err)
	}
	if string(content) != "normal-content" {
		t.Fatalf("readRuleSource content = %q, want %q", string(content), "normal-content")
	}

	// 2. Traversal paths must be rejected with os.ErrInvalid and must not read the secret file
	traversalTests := []string{
		"../secret.txt",
		"../../secret.txt",
		"/secret.txt",
		filepath.Join(tempDir, "secret.txt"),
		"",
		".",
		"sub/../../secret.txt",
	}

	for _, badPath := range traversalTests {
		t.Run(badPath, func(t *testing.T) {
			data, err := readRuleSource(repoDir, badPath, true)
			if !errors.Is(err, os.ErrInvalid) {
				t.Errorf("readRuleSource(%q) err = %v, want os.ErrInvalid", badPath, err)
			}
			if data != nil {
				t.Errorf("readRuleSource(%q) returned data = %q, want nil", badPath, string(data))
			}
		})
	}
}
