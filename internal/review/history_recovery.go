package review

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// RecoverHistory rebuilds the history log non-destructively from valid report files.
// It writes to a temporary file, validates all entries, eliminates duplicate RunIDs deterministically,
// and atomically replaces history.jsonl only after success. If no valid reports exist or an error
// occurs, the original history is preserved.
//
// Durability: File data is guaranteed via tempFile.Sync() prior to atomic rename. Parent directory sync
// is best-effort across platforms.
func RecoverHistory(reportsDir string, historyPath string) (int, error) {
	if reportsDir == "" {
		return 0, fmt.Errorf("reports directory cannot be empty")
	}
	if historyPath == "" {
		return 0, fmt.Errorf("history path cannot be empty")
	}

	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read reports directory: %w", err)
	}

	type reportCandidate struct {
		entry    HistoryEntry
		fileName string
	}
	candidates := make(map[string]reportCandidate)

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		reportPath := filepath.Join(reportsDir, entry.Name())
		report, err := ReadReport(reportPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to read report %s: %v\n", entry.Name(), err)
			continue
		}

		if report.RunID == "" || !IsValidRunID(report.RunID) || report.Timestamp.IsZero() {
			fmt.Fprintf(os.Stderr, "Warning: skipping invalid report %s: invalid metadata\n", entry.Name())
			continue
		}

		newEntry := NewHistoryEntry(report)
		existing, found := candidates[report.RunID]
		if found {
			// Deterministic duplicate resolution:
			// 1. Prefer canonical filename matching <RunID>.json
			// 2. Prefer newer timestamp
			// 3. Prefer lexicographically smaller filename
			canonicalName := report.RunID + ".json"
			replace := false
			if entry.Name() == canonicalName && existing.fileName != canonicalName {
				replace = true
			} else if existing.fileName != canonicalName {
				if newEntry.Timestamp.After(existing.entry.Timestamp) {
					replace = true
				} else if newEntry.Timestamp.Equal(existing.entry.Timestamp) && entry.Name() < existing.fileName {
					replace = true
				}
			}

			if replace {
				fmt.Fprintf(os.Stderr, "Warning: duplicate report for run ID %s found in %s; replacing entry from %s\n", report.RunID, entry.Name(), existing.fileName)
				candidates[report.RunID] = reportCandidate{entry: newEntry, fileName: entry.Name()}
			} else {
				fmt.Fprintf(os.Stderr, "Warning: duplicate report for run ID %s found in %s; keeping preferred entry from %s\n", report.RunID, entry.Name(), existing.fileName)
			}
			continue
		}

		candidates[report.RunID] = reportCandidate{entry: newEntry, fileName: entry.Name()}
	}

	if len(candidates) == 0 {
		return 0, nil
	}

	var recoveredEntries []HistoryEntry
	for _, c := range candidates {
		recoveredEntries = append(recoveredEntries, c.entry)
	}

	// Sort entries chronologically by timestamp, then by RunID for strict determinism
	sort.Slice(recoveredEntries, func(i, j int) bool {
		if recoveredEntries[i].Timestamp.Equal(recoveredEntries[j].Timestamp) {
			return recoveredEntries[i].RunID < recoveredEntries[j].RunID
		}
		return recoveredEntries[i].Timestamp.Before(recoveredEntries[j].Timestamp)
	})

	historyDir := filepath.Dir(historyPath)
	if err := os.MkdirAll(historyDir, 0755); err != nil {
		return 0, fmt.Errorf("create history directory: %w", err)
	}

	tempFile, err := os.CreateTemp(historyDir, "history-recovery-*.tmp")
	if err != nil {
		return 0, fmt.Errorf("create temporary history file: %w", err)
	}
	tempPath := tempFile.Name()

	cleanup := true
	defer func() {
		if cleanup {
			tempFile.Close()
			os.Remove(tempPath)
		}
	}()

	if err := tempFile.Chmod(0644); err != nil {
		return 0, fmt.Errorf("chmod temporary history file: %w", err)
	}

	for _, entry := range recoveredEntries {
		data, err := json.Marshal(entry)
		if err != nil {
			return 0, fmt.Errorf("marshal history entry: %w", err)
		}
		if _, err := tempFile.Write(append(data, '\n')); err != nil {
			return 0, fmt.Errorf("write history entry: %w", err)
		}
	}

	if err := tempFile.Sync(); err != nil {
		return 0, fmt.Errorf("sync temporary history file: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return 0, fmt.Errorf("close temporary history file: %w", err)
	}

	if err := os.Rename(tempPath, historyPath); err != nil {
		return 0, fmt.Errorf("atomically replace history file: %w", err)
	}

	cleanup = false

	if parentDir, err := os.Open(historyDir); err == nil {
		_ = parentDir.Sync()
		_ = parentDir.Close()
	}

	return len(recoveredEntries), nil
}
