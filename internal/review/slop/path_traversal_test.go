package slop

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSlopRulePathTraversal(t *testing.T) {
	tempDir := t.TempDir()
	secretFile := filepath.Join(tempDir, "secret.py")
	// Put slop content inside the secret outside repo root
	if err := os.WriteFile(secretFile, []byte("x = True == True\n"), 0644); err != nil {
		t.Fatalf("failed to write secret file: %v", err)
	}

	repoDir := filepath.Join(tempDir, "repo")
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		t.Fatalf("failed to create repo dir: %v", err)
	}

	rule := SlopRule{
		RepositoryRoot: repoDir,
		WorkingTree:    true,
	}

	traversalTests := []string{
		"../secret.py",
		"../../secret.py",
		"/secret.py",
		"",
		".",
		"sub/../../secret.py",
	}

	for _, badPath := range traversalTests {
		t.Run(badPath, func(t *testing.T) {
			data, err := rule.readSourceForAnalysis(badPath)
			if !errors.Is(err, os.ErrInvalid) {
				t.Errorf("readSourceForAnalysis(%q) err = %v, want os.ErrInvalid", badPath, err)
			}
			if data != nil {
				t.Errorf("readSourceForAnalysis(%q) returned data = %q, want nil", badPath, string(data))
			}

			dataImplicit, errImplicit := rule.readImplicitSource(badPath)
			if !errors.Is(errImplicit, os.ErrInvalid) {
				t.Errorf("readImplicitSource(%q) err = %v, want os.ErrInvalid", badPath, errImplicit)
			}
			if dataImplicit != nil {
				t.Errorf("readImplicitSource(%q) returned data = %q, want nil", badPath, string(dataImplicit))
			}

			findings := rule.checkGoFileAST(badPath, []int{1})
			if len(findings) == 0 {
				t.Errorf("checkGoFileAST(%q) expected error findings, got none", badPath)
			} else if findings[0].Rule != "code-slop-analysis-error" {
				t.Errorf("checkGoFileAST(%q) rule = %q, want %q", badPath, findings[0].Rule, "code-slop-analysis-error")
			}
		})
	}
}
