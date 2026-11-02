package review

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

func ReadHistory(path string) ([]HistoryEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []HistoryEntry{}, nil
		}

		return nil, fmt.Errorf("open history file: %w", err)
	}
	defer file.Close()

	var entries []HistoryEntry
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		var entry HistoryEntry

		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			// Skip corrupt or unparseable lines gracefully to keep history usable
			continue
		}

		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read history file: %w", err)
	}

	return entries, nil
}
