package review

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupTestHistoryRepo(t *testing.T, count int) (string, []string, time.Time) {
	t.Helper()
	repoDir := t.TempDir()
	reportsDir := filepath.Join(repoDir, ".m3tal-review", "reports")
	historyPath := filepath.Join(repoDir, ".m3tal-review", "history.jsonl")

	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	baseTime := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	var runIDs []string

	for i := 0; i < count; i++ {
		runID := fmt.Sprintf("%016x", i+1)
		runIDs = append(runIDs, runID)
		entryTime := baseTime.Add(time.Duration(i) * 24 * time.Hour) // 1 day apart

		rep := NewReport(runID, "repo", "main", "c1", "c0", "d1", "1.0", []string{"a.go"}, nil)
		rep.Timestamp = entryTime
		repPath := filepath.Join(reportsDir, runID+".json")
		if err := WriteReport(repPath, rep); err != nil {
			t.Fatalf("write report failed: %v", err)
		}

		entry := NewHistoryEntry(rep)
		entry.Timestamp = entryTime
		if err := AppendHistory(historyPath, entry); err != nil {
			t.Fatalf("append history failed: %v", err)
		}
	}

	return repoDir, runIDs, baseTime
}

func TestHistoryPrune_OlderThan(t *testing.T) {
	repoDir, runIDs, baseTime := setupTestHistoryRepo(t, 5)
	// Entries at: Day 0, Day 1, Day 2, Day 3, Day 4.
	// Current time: Day 4 + 12h.
	now := baseTime.Add(4*24*time.Hour + 12*time.Hour)

	// Prune older than 2 days (48h)
	olderThan := 48 * time.Hour
	opts := PruneOptions{
		OlderThan: &olderThan,
		Now:       now,
	}

	res, err := PruneHistory(repoDir, opts)
	if err != nil {
		t.Fatalf("PruneHistory error: %v", err)
	}

	// Day 0, Day 1, Day 2 are older than 48h from Day 4.5.
	// Retained should be Day 3 and Day 4 (2 entries).
	if res.PrunedEntries != 3 || res.RetainedEntries != 2 {
		t.Errorf("unexpected counts: pruned=%d (want 3), retained=%d (want 2)", res.PrunedEntries, res.RetainedEntries)
	}

	// Verify history.jsonl
	historyPath := filepath.Join(repoDir, ".m3tal-review", "history.jsonl")
	entries, err := ReadHistory(historyPath)
	if err != nil {
		t.Fatalf("read history failed: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries in history, got %d", len(entries))
	}

	// Verify deleted reports
	reportsDir := filepath.Join(repoDir, ".m3tal-review", "reports")
	for i := 0; i < 3; i++ {
		p := filepath.Join(reportsDir, runIDs[i]+".json")
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expected report %s to be deleted", runIDs[i])
		}
	}
	for i := 3; i < 5; i++ {
		p := filepath.Join(reportsDir, runIDs[i]+".json")
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected report %s to exist: %v", runIDs[i], err)
		}
	}
}

func TestHistoryPrune_KeepCount(t *testing.T) {
	repoDir, _, baseTime := setupTestHistoryRepo(t, 5)
	now := baseTime.Add(4*24*time.Hour + 12*time.Hour)

	// Older than 1h (would prune all), but keep = 3
	olderThan := 1 * time.Hour
	keep := 3
	opts := PruneOptions{
		OlderThan: &olderThan,
		Keep:      &keep,
		Now:       now,
	}

	res, err := PruneHistory(repoDir, opts)
	if err != nil {
		t.Fatalf("PruneHistory error: %v", err)
	}

	// Must keep top 3 newest entries (Days 4, 3, 2), prune Days 0 and 1
	if res.PrunedEntries != 2 || res.RetainedEntries != 3 {
		t.Errorf("unexpected counts: pruned=%d (want 2), retained=%d (want 3)", res.PrunedEntries, res.RetainedEntries)
	}
}

func TestHistoryPrune_DryRun(t *testing.T) {
	repoDir, runIDs, baseTime := setupTestHistoryRepo(t, 5)
	now := baseTime.Add(4*24*time.Hour + 12*time.Hour)

	olderThan := 48 * time.Hour
	opts := PruneOptions{
		OlderThan: &olderThan,
		DryRun:    true,
		Now:       now,
	}

	res, err := PruneHistory(repoDir, opts)
	if err != nil {
		t.Fatalf("PruneHistory error: %v", err)
	}

	if !res.DryRun {
		t.Errorf("expected DryRun = true")
	}
	if res.PrunedEntries != 3 {
		t.Errorf("expected 3 entries marked for pruning, got %d", res.PrunedEntries)
	}

	// In dry run, history.jsonl and all report files must still exist!
	historyPath := filepath.Join(repoDir, ".m3tal-review", "history.jsonl")
	entries, _ := ReadHistory(historyPath)
	if len(entries) != 5 {
		t.Errorf("expected 5 entries in history during dry-run, got %d", len(entries))
	}

	reportsDir := filepath.Join(repoDir, ".m3tal-review", "reports")
	for _, id := range runIDs {
		p := filepath.Join(reportsDir, id+".json")
		if _, err := os.Stat(p); err != nil {
			t.Errorf("report %s was deleted during dry-run!", id)
		}
	}
}

func TestHistoryPrune_MaxSize(t *testing.T) {
	repoDir, _, baseTime := setupTestHistoryRepo(t, 4)
	now := baseTime.Add(4 * 24 * time.Hour)

	// Stat report size
	reportsDir := filepath.Join(repoDir, ".m3tal-review", "reports")
	entries, _ := os.ReadDir(reportsDir)
	if len(entries) == 0 {
		t.Fatalf("no reports found")
	}
	info, _ := entries[0].Info()
	singleSize := info.Size()

	// Set max size to allow only 2 reports
	maxSize := singleSize*2 + 10
	opts := PruneOptions{
		MaxSize: &maxSize,
		Now:     now,
	}

	res, err := PruneHistory(repoDir, opts)
	if err != nil {
		t.Fatalf("PruneHistory error: %v", err)
	}

	if res.RetainedEntries != 2 || res.PrunedEntries != 2 {
		t.Errorf("expected 2 retained and 2 pruned by max-size, got retained=%d, pruned=%d", res.RetainedEntries, res.PrunedEntries)
	}
}

func TestHistoryPrune_NeverDeletesRecoveryCriticalArtifacts(t *testing.T) {
	repoDir, _, baseTime := setupTestHistoryRepo(t, 3)
	now := baseTime.Add(10 * 24 * time.Hour)

	// Put extra recovery/critical files in .m3tal-review
	criticalDir := filepath.Join(repoDir, ".m3tal-review")
	lockFile := filepath.Join(criticalDir, "history.lock")
	_ = os.WriteFile(lockFile, []byte("active-lock"), 0644)
	otherDir := filepath.Join(criticalDir, "suppressions")
	_ = os.MkdirAll(otherDir, 0755)
	auditFile := filepath.Join(otherDir, "audit.jsonl")
	_ = os.WriteFile(auditFile, []byte("audit"), 0644)

	// Prune all reports (older than 1h, keep=0)
	olderThan := 1 * time.Hour
	opts := PruneOptions{
		OlderThan: &olderThan,
		Now:       now,
	}

	res, err := PruneHistory(repoDir, opts)
	if err != nil {
		t.Fatalf("prune failed: %v", err)
	}
	if res.PrunedEntries != 3 {
		t.Errorf("expected 3 pruned entries, got %d", res.PrunedEntries)
	}

	// Check that lockFile, otherDir, auditFile, and history.jsonl are all still present
	if _, err := os.Stat(lockFile); err != nil {
		t.Errorf("lockFile was unexpectedly removed: %v", err)
	}
	if _, err := os.Stat(auditFile); err != nil {
		t.Errorf("auditFile was unexpectedly removed: %v", err)
	}
	historyPath := filepath.Join(criticalDir, "history.jsonl")
	if _, err := os.Stat(historyPath); err != nil {
		t.Errorf("history.jsonl was unexpectedly removed: %v", err)
	}
}

func TestHistoryPrune_ParseHelpers(t *testing.T) {
	// Duration parsing
	d, err := ParseRetentionDuration("30d")
	if err != nil || d != 30*24*time.Hour {
		t.Errorf("ParseRetentionDuration(30d) = %v, %v", d, err)
	}
	d, err = ParseRetentionDuration("2w")
	if err != nil || d != 14*24*time.Hour {
		t.Errorf("ParseRetentionDuration(2w) = %v, %v", d, err)
	}
	d, err = ParseRetentionDuration("1y")
	if err != nil || d != 365*24*time.Hour {
		t.Errorf("ParseRetentionDuration(1y) = %v, %v", d, err)
	}
	d, err = ParseRetentionDuration("72h")
	if err != nil || d != 72*time.Hour {
		t.Errorf("ParseRetentionDuration(72h) = %v, %v", d, err)
	}
	if _, err := ParseRetentionDuration("invalid"); err == nil {
		t.Errorf("expected invalid duration to fail")
	}

	// Size parsing
	sz, err := ParseRetentionSize("10MB")
	if err != nil || sz != 10*1024*1024 {
		t.Errorf("ParseRetentionSize(10MB) = %d, %v", sz, err)
	}
	sz, err = ParseRetentionSize("500KB")
	if err != nil || sz != 500*1024 {
		t.Errorf("ParseRetentionSize(500KB) = %d, %v", sz, err)
	}
	sz, err = ParseRetentionSize("1GB")
	if err != nil || sz != 1024*1024*1024 {
		t.Errorf("ParseRetentionSize(1GB) = %d, %v", sz, err)
	}
	sz, err = ParseRetentionSize("2048")
	if err != nil || sz != 2048 {
		t.Errorf("ParseRetentionSize(2048) = %d, %v", sz, err)
	}
	if _, err := ParseRetentionSize("invalid"); err == nil {
		t.Errorf("expected invalid size to fail")
	}
}
