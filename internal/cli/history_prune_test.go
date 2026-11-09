package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func setupCLIHistoryRepo(t *testing.T, count int) (string, []string) {
	t.Helper()
	repoDir := t.TempDir()
	if out, err := exec.Command("git", "init", repoDir).CombinedOutput(); err != nil {
		t.Fatalf("git init failed: %v, out: %s", err, string(out))
	}

	reportsDir := filepath.Join(repoDir, ".m3tal-review", "reports")
	historyPath := filepath.Join(repoDir, ".m3tal-review", "history.jsonl")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	baseTime := time.Now().UTC().Add(-time.Duration(count+1) * 24 * time.Hour)
	var runIDs []string

	for i := 0; i < count; i++ {
		runID := fmt.Sprintf("%016x", i+1)
		runIDs = append(runIDs, runID)
		entryTime := baseTime.Add(time.Duration(i) * 24 * time.Hour)

		rep := review.NewReport(runID, "repo", "main", "c1", "c0", "d1", "1.0", []string{"a.go"}, nil)
		rep.Timestamp = entryTime
		repPath := filepath.Join(reportsDir, runID+".json")
		if err := review.WriteReport(repPath, rep); err != nil {
			t.Fatalf("write report failed: %v", err)
		}

		entry := review.NewHistoryEntry(rep)
		entry.Timestamp = entryTime
		if err := review.AppendHistory(historyPath, entry); err != nil {
			t.Fatalf("append history failed: %v", err)
		}
	}

	return repoDir, runIDs
}

func TestCLI_HistoryPrune(t *testing.T) {
	repoDir, _ := setupCLIHistoryRepo(t, 5)

	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd failed: %v", err)
	}
	defer func() { _ = os.Chdir(origWd) }()

	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}

	// 1. Dry run test
	outDryRun, err := captureOutput(func() error {
		return Run([]string{"history", "prune", "--older-than", "24h", "--dry-run"})
	})
	if err != nil {
		t.Fatalf("history prune --dry-run failed: %v", err)
	}
	if !strings.Contains(outDryRun, "DRY RUN") {
		t.Errorf("expected output to contain DRY RUN, got:\n%s", outDryRun)
	}

	// 2. JSON format test
	outJSON, err := captureOutput(func() error {
		return Run([]string{"history", "prune", "--keep", "2", "--format", "json"})
	})
	if err != nil {
		t.Fatalf("history prune --keep 2 --format json failed: %v", err)
	}
	if !strings.Contains(outJSON, `"retained_entries": 2`) || !strings.Contains(outJSON, `"pruned_entries": 3`) {
		t.Errorf("unexpected json output:\n%s", outJSON)
	}

	// 3. Verify history now has 2 entries
	historyPath := filepath.Join(repoDir, ".m3tal-review", "history.jsonl")
	entries, err := review.ReadHistory(historyPath)
	if err != nil {
		t.Fatalf("read history failed: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries in history after prune, got %d", len(entries))
	}

	// 4. Missing retention option error
	_, err = captureOutput(func() error {
		return Run([]string{"history", "prune"})
	})
	if err == nil {
		t.Errorf("expected error when no retention flags passed")
	}

	// 5. Help output
	outHelp, err := captureOutput(func() error {
		return Run([]string{"history", "prune", "--help"})
	})
	if err != nil {
		t.Errorf("expected --help to succeed: %v", err)
	}
	if !strings.Contains(outHelp, "Usage:") {
		t.Errorf("expected usage instructions in help, got:\n%s", outHelp)
	}
}
