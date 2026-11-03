package review

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// AppendHistory appends a new HistoryEntry to the history.jsonl log file.
//
// Durability Guarantees:
// 1. File payload durability: file contents are flushed and synced via fsync (syncFile) before closing.
// 2. Directory entry durability: if the file was newly created, parent directory is synced.
// 3. Best-effort directory sync: directory sync failure emits a warning to os.Stderr without failing the append.
// 4. Data integrity: existing history entries are preserved if appending, syncing, or closing fails.
func AppendHistory(path string, entry HistoryEntry) error {
	return appendHistoryWithFS(path, entry, defaultFSOps())
}

func appendHistoryWithFS(path string, entry HistoryEntry, ops fsOps) (retErr error) {
	ops = ops.withDefaults()

	if path == "" {
		return fmt.Errorf("history path cannot be empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create history directory: %w", err)
	}

	unlock, err := lockHistory(path)
	if err != nil {
		return fmt.Errorf("lock history file: %w", err)
	}
	defer unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal history entry: %w", err)
	}

	var fileExisted bool
	initialSize := int64(0)
	if info, err := ops.statFile(path); err == nil {
		fileExisted = true
		initialSize = info.Size()
	} else if os.IsNotExist(err) {
		fileExisted = false
	} else {
		return fmt.Errorf("stat history file: %w", err)
	}

	file, err := ops.openFile(
		path,
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)
	if err != nil {
		return fmt.Errorf("open history file: %w", err)
	}

	success := false
	fileClosed := false

	defer func() {
		if success {
			return
		}

		var rollbackErrs []error
		if fileExisted {
			targetFile := file
			if fileClosed {
				reopened, err := ops.openFile(path, os.O_WRONLY, 0644)
				if err != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback open: %w", err))
					targetFile = nil
				} else {
					targetFile = reopened
				}
			}

			if targetFile != nil {
				if err := ops.truncateFile(targetFile, initialSize); err != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback truncate: %w", err))
				}
				if err := ops.syncFile(targetFile); err != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback sync: %w", err))
				}
				if err := ops.closeFile(targetFile); err != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback close: %w", err))
				}
			}
		} else {
			if !fileClosed {
				if err := ops.closeFile(file); err != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback close: %w", err))
				}
				fileClosed = true
			}
			if err := ops.removeFile(path); err != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback remove: %w", err))
			}
		}

		if len(rollbackErrs) > 0 {
			allErrs := append([]error{retErr}, rollbackErrs...)
			retErr = errors.Join(allErrs...)
		}
	}()

	if _, err := ops.writeFile(file, append(data, '\n')); err != nil {
		retErr = fmt.Errorf("append history entry: %w", err)
		return retErr
	}

	if err := ops.syncFile(file); err != nil {
		retErr = fmt.Errorf("sync history file: %w", err)
		return retErr
	}

	fileClosed = true
	if err := ops.closeFile(file); err != nil {
		retErr = fmt.Errorf("close history file: %w", err)
		return retErr
	}

	success = true

	if !fileExisted {
		if err := ops.syncDir(dir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to sync directory %s: %s\n", safeTerminalText(dir), safeTerminalText(err.Error()))
		}
	}

	return nil
}
