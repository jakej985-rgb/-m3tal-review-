package review

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type PruneOptions struct {
	OlderThan *time.Duration `json:"older_than,omitempty"`
	Keep      *int           `json:"keep,omitempty"`
	MaxSize   *int64         `json:"max_size,omitempty"`
	DryRun    bool           `json:"dry_run"`
	Now       time.Time      `json:"now,omitempty"`
}

type PruneItem struct {
	RunID     string    `json:"run_id"`
	Timestamp time.Time `json:"timestamp"`
	Path      string    `json:"path,omitempty"`
	SizeBytes int64     `json:"size_bytes"`
	Reason    string    `json:"reason"`
}

type PruneResult struct {
	DryRun          bool        `json:"dry_run"`
	InitialEntries  int         `json:"initial_entries"`
	RetainedEntries int         `json:"retained_entries"`
	PrunedEntries   int         `json:"pruned_entries"`
	DeletedReports  int         `json:"deleted_reports"`
	BytesReclaimed  int64       `json:"bytes_reclaimed"`
	Pruned          []PruneItem `json:"pruned,omitempty"`
}

// ParseRetentionDuration parses strings like "30d", "24h", "2w", "1y", "90m".
func ParseRetentionDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("duration cannot be empty")
	}

	// Check custom suffix: d (days), w (weeks), y (years)
	lower := strings.ToLower(s)
	if strings.HasSuffix(lower, "d") {
		daysStr := strings.TrimSuffix(lower, "d")
		days, err := strconv.ParseFloat(daysStr, 64)
		if err != nil || days < 0 {
			return 0, fmt.Errorf("invalid days duration %q", s)
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	if strings.HasSuffix(lower, "w") {
		weeksStr := strings.TrimSuffix(lower, "w")
		weeks, err := strconv.ParseFloat(weeksStr, 64)
		if err != nil || weeks < 0 {
			return 0, fmt.Errorf("invalid weeks duration %q", s)
		}
		return time.Duration(weeks * float64(7*24*time.Hour)), nil
	}
	if strings.HasSuffix(lower, "y") {
		yearsStr := strings.TrimSuffix(lower, "y")
		years, err := strconv.ParseFloat(yearsStr, 64)
		if err != nil || years < 0 {
			return 0, fmt.Errorf("invalid years duration %q", s)
		}
		return time.Duration(years * float64(365*24*time.Hour)), nil
	}

	// Standard Go duration
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}
	return d, nil
}

// ParseRetentionSize parses strings like "10MB", "500KB", "1GB", "1048576".
func ParseRetentionSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, fmt.Errorf("size cannot be empty")
	}

	multiplier := int64(1)
	clean := s

	switch {
	case strings.HasSuffix(s, "GB") || strings.HasSuffix(s, "G"):
		multiplier = 1024 * 1024 * 1024
		clean = strings.TrimSuffix(strings.TrimSuffix(s, "GB"), "G")
	case strings.HasSuffix(s, "MB") || strings.HasSuffix(s, "M"):
		multiplier = 1024 * 1024
		clean = strings.TrimSuffix(strings.TrimSuffix(s, "MB"), "M")
	case strings.HasSuffix(s, "KB") || strings.HasSuffix(s, "K"):
		multiplier = 1024
		clean = strings.TrimSuffix(strings.TrimSuffix(s, "KB"), "K")
	case strings.HasSuffix(s, "B"):
		multiplier = 1
		clean = strings.TrimSuffix(s, "B")
	}

	val, err := strconv.ParseFloat(strings.TrimSpace(clean), 64)
	if err != nil || val < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}

	return int64(val * float64(multiplier)), nil
}

// PruneHistory prunes history entries and associated report files according to retention criteria.
// It is deterministic, safe, atomic, and strictly protects non-target recovery artifacts.
func PruneHistory(repositoryRoot string, opts PruneOptions) (PruneResult, error) {
	return pruneHistoryWithFS(repositoryRoot, opts, defaultFSOps())
}

func pruneHistoryWithFS(repositoryRoot string, opts PruneOptions, ops fsOps) (PruneResult, error) {
	ops = ops.withDefaults()

	if repositoryRoot == "" {
		return PruneResult{}, fmt.Errorf("repository root cannot be empty")
	}

	if opts.OlderThan == nil && opts.Keep == nil && opts.MaxSize == nil {
		return PruneResult{}, fmt.Errorf("at least one retention option (--older-than, --keep, --max-size) is required")
	}

	if opts.Keep != nil && *opts.Keep < 0 {
		return PruneResult{}, fmt.Errorf("--keep must be non-negative: %d", *opts.Keep)
	}

	if opts.MaxSize != nil && *opts.MaxSize < 0 {
		return PruneResult{}, fmt.Errorf("--max-size must be non-negative: %d", *opts.MaxSize)
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	historyPath := filepath.Join(repositoryRoot, ".m3tal-review", "history.jsonl")
	reportsDir := filepath.Join(repositoryRoot, ".m3tal-review", "reports")

	// Acquire lock on history
	unlock, err := lockHistory(historyPath)
	if err != nil {
		return PruneResult{}, fmt.Errorf("lock history for pruning: %w", err)
	}
	defer unlock()

	entries, err := ReadHistory(historyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return PruneResult{DryRun: opts.DryRun}, nil
		}
		return PruneResult{}, fmt.Errorf("read history: %w", err)
	}

	if len(entries) == 0 {
		return PruneResult{DryRun: opts.DryRun}, nil
	}

	// Sort entries deterministically: newest first, tie-break by RunID
	type entryWithMeta struct {
		entry      HistoryEntry
		reportPath string
		sizeBytes  int64
		exists     bool
		prune      bool
		reason     string
	}

	items := make([]entryWithMeta, len(entries))
	for i, e := range entries {
		repPath := filepath.Join(reportsDir, e.RunID+".json")
		var size int64
		exists := false
		if info, err := os.Stat(repPath); err == nil && !info.IsDir() {
			size = info.Size()
			exists = true
		}
		items[i] = entryWithMeta{
			entry:      e,
			reportPath: repPath,
			sizeBytes:  size,
			exists:     exists,
		}
	}

	// Sort newest first
	sort.Slice(items, func(i, j int) bool {
		if items[i].entry.Timestamp.Equal(items[j].entry.Timestamp) {
			return items[i].entry.RunID < items[j].entry.RunID
		}
		return items[i].entry.Timestamp.After(items[j].entry.Timestamp)
	})

	keepCount := 0
	if opts.Keep != nil {
		keepCount = *opts.Keep
	}
	if keepCount > len(items) {
		keepCount = len(items)
	}

	// 1. Evaluate OlderThan on entries outside the keepCount window
	if opts.OlderThan != nil {
		cutoff := now.Add(-*opts.OlderThan)
		for i := keepCount; i < len(items); i++ {
			if items[i].entry.Timestamp.Before(cutoff) {
				items[i].prune = true
				items[i].reason = fmt.Sprintf("older than %s", opts.OlderThan.String())
			}
		}
	} else if opts.MaxSize == nil && opts.Keep != nil {
		// When keep is specified without older-than or max-size, prune all entries beyond keep count
		for i := keepCount; i < len(items); i++ {
			items[i].prune = true
			items[i].reason = fmt.Sprintf("exceeds keep count %d", keepCount)
		}
	}

	// 2. Evaluate MaxSize on all retained entries outside the keepCount window
	if opts.MaxSize != nil {
		// Calculate total size of reports of retained items
		var totalRetainedSize int64
		for _, it := range items {
			if !it.prune {
				totalRetainedSize += it.sizeBytes
			}
		}

		// Prune from oldest to newest beyond keepCount until totalRetainedSize <= *opts.MaxSize
		for i := len(items) - 1; i >= keepCount; i-- {
			if totalRetainedSize <= *opts.MaxSize {
				break
			}
			if !items[i].prune {
				items[i].prune = true
				items[i].reason = fmt.Sprintf("exceeds max retention size %d bytes", *opts.MaxSize)
				totalRetainedSize -= items[i].sizeBytes
			}
		}
	}

	// Collect pruned items and retained entries
	res := PruneResult{
		DryRun:         opts.DryRun,
		InitialEntries: len(items),
	}

	var retainedEntries []HistoryEntry
	for _, it := range items {
		if it.prune {
			res.PrunedEntries++
			res.BytesReclaimed += it.sizeBytes
			if it.exists {
				res.DeletedReports++
			}
			res.Pruned = append(res.Pruned, PruneItem{
				RunID:     it.entry.RunID,
				Timestamp: it.entry.Timestamp,
				Path:      it.reportPath,
				SizeBytes: it.sizeBytes,
				Reason:    it.reason,
			})
		} else {
			retainedEntries = append(retainedEntries, it.entry)
			res.RetainedEntries++
		}
	}

	if opts.DryRun || res.PrunedEntries == 0 {
		return res, nil
	}

	// Atomic rewrite of history.jsonl
	// Sort retained entries chronologically (oldest first) as expected in history.jsonl
	sort.Slice(retainedEntries, func(i, j int) bool {
		if retainedEntries[i].Timestamp.Equal(retainedEntries[j].Timestamp) {
			return retainedEntries[i].RunID < retainedEntries[j].RunID
		}
		return retainedEntries[i].Timestamp.Before(retainedEntries[j].Timestamp)
	})

	historyDir := filepath.Dir(historyPath)
	tempFile, err := os.CreateTemp(historyDir, "history-prune-*.tmp")
	if err != nil {
		return res, fmt.Errorf("create temporary history file: %w", err)
	}
	tempPath := tempFile.Name()

	cleanup := true
	defer func() {
		if cleanup {
			_ = ops.closeFile(tempFile)
			_ = ops.removeFile(tempPath)
		}
	}()

	if err := tempFile.Chmod(0644); err != nil {
		return res, fmt.Errorf("chmod temporary history file: %w", err)
	}

	for _, entry := range retainedEntries {
		data, err := json.Marshal(entry)
		if err != nil {
			return res, fmt.Errorf("marshal history entry: %w", err)
		}
		if _, err := ops.writeFile(tempFile, append(data, '\n')); err != nil {
			return res, fmt.Errorf("write history entry: %w", err)
		}
	}

	if err := ops.syncFile(tempFile); err != nil {
		return res, fmt.Errorf("sync temporary history file: %w", err)
	}

	if err := ops.closeFile(tempFile); err != nil {
		return res, fmt.Errorf("close temporary history file: %w", err)
	}

	if err := ops.renameFile(tempPath, historyPath); err != nil {
		return res, fmt.Errorf("atomically replace history file: %w", err)
	}

	cleanup = false
	_ = ops.syncDir(historyDir)

	// Safely delete pruned report files
	actualDeleted := 0
	for _, it := range res.Pruned {
		if it.Path != "" {
			// Ensure it's inside reportsDir and ends with .json to prevent accidental deletion
			if filepath.Dir(it.Path) == reportsDir && strings.HasSuffix(it.Path, ".json") {
				if err := os.Remove(it.Path); err == nil {
					actualDeleted++
				}
			}
		}
	}
	res.DeletedReports = actualDeleted

	return res, nil
}
