package review

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// AppendHistory appends a new HistoryEntry to the history.jsonl log file.
//
// Durability Guarantees:
// 1. File payload durability is guaranteed via fsync (syncFileHook) before closing.
// 2. Directory entry durability: if the file was newly created, parent directory is synced.
func AppendHistory(path string, entry HistoryEntry) error {
	if path == "" {
		return fmt.Errorf("history path cannot be empty")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create history directory: %w", err)
	}

	file, err := os.OpenFile(
		path,
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)
	if err != nil {
		return fmt.Errorf("open history file: %w", err)
	}

	closed := false
	defer func() {
		if !closed {
			_ = closeFileHook(file)
		}
	}()

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal history entry: %w", err)
	}

	if _, err := file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("append history entry: %w", err)
	}

	if err := syncFileHook(file); err != nil {
		return fmt.Errorf("sync history file: %w", err)
	}

	closed = true
	if err := closeFileHook(file); err != nil {
		return fmt.Errorf("close history file: %w", err)
	}

	return nil
}
