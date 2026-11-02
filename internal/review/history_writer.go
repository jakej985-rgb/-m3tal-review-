package review

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

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
	defer file.Close()

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal history entry: %w", err)
	}

	if _, err := file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("append history entry: %w", err)
	}

	return nil
}
