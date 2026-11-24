package history

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jakej985-rgb/m3tal-review/internal/review/fsutil"
	"github.com/jakej985-rgb/m3tal-review/internal/review/safetext"
)

// AppendHistory appends a new HistoryEntry to the history.jsonl log file.
//
// Durability Guarantees:
// 1. File payload durability: file contents are flushed and synced via fsync (SyncFile) before closing.
// 2. Directory entry durability: if the file was newly created, parent directory is synced.
// 3. Best-effort directory sync: directory sync failure emits a warning to os.Stderr without failing the append.
// 4. Data integrity: existing history entries are preserved if appending, syncing, or closing fails.
func AppendHistory(path string, entry HistoryEntry) error {
	return AppendHistoryWithOps(path, entry, fsutil.Default())
}

func AppendHistoryWithOps(path string, entry HistoryEntry, ops fsutil.Ops) (retErr error) {
	ops = fsutil.WithDefaults(ops)

	if path == "" {
		return fmt.Errorf("history path cannot be empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create history directory: %w", err)
	}

	unlock, err := Lock(path)
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
	if info, err := ops.StatFile(path); err == nil {
		fileExisted = true
		initialSize = info.Size()
	} else if os.IsNotExist(err) {
		fileExisted = false
	} else {
		return fmt.Errorf("stat history file: %w", err)
	}

	file, err := ops.OpenFile(
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
			// Truncate requires write access that the O_APPEND handle lacks on
			// Windows (FILE_APPEND_DATA only), so rollback always uses a fresh
			// O_WRONLY handle.
			if !fileClosed {
				if err := ops.CloseFile(file); err != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback close: %w", err))
				}
				fileClosed = true
			}

			reopened, err := ops.OpenFile(path, os.O_WRONLY, 0644)
			if err != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback open: %w", err))
			} else {
				if err := ops.TruncateFile(reopened, initialSize); err != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback truncate: %w", err))
				}
				if err := ops.SyncFile(reopened); err != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback sync: %w", err))
				}
				if err := ops.CloseFile(reopened); err != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback close: %w", err))
				}
			}
		} else {
			if !fileClosed {
				if err := ops.CloseFile(file); err != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback close: %w", err))
				}
				fileClosed = true
			}
			if err := ops.RemoveFile(path); err != nil {
				rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback remove: %w", err))
			}
		}

		if len(rollbackErrs) > 0 {
			allErrs := append([]error{retErr}, rollbackErrs...)
			retErr = errors.Join(allErrs...)
		}
	}()

	if _, err := ops.WriteFile(file, append(data, '\n')); err != nil {
		retErr = fmt.Errorf("append history entry: %w", err)
		return retErr
	}

	if err := ops.SyncFile(file); err != nil {
		retErr = fmt.Errorf("sync history file: %w", err)
		return retErr
	}

	fileClosed = true
	if err := ops.CloseFile(file); err != nil {
		retErr = fmt.Errorf("close history file: %w", err)
		return retErr
	}

	success = true

	if !fileExisted {
		if err := ops.SyncDir(dir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to sync directory %s: %s\n", safetext.Terminal(dir), safetext.Terminal(err.Error()))
		}
	}

	return nil
}
