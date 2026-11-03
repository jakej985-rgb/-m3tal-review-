package review

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// WriteReport writes a review report atomically to the specified path.
//
// Durability & Atomicity Design:
//  1. File payload persistence: file contents are flushed and synced via fsync (syncFileHook)
//     prior to closing and renaming. Write, sync, and close errors fail the operation immediately.
//  2. Atomicity: The report is written to a temporary file in the target directory and moved into
//     place using atomic rename (renameFileHook).
//  3. Directory sync: Parent directory syncing (syncDirHook) is best-effort. Unsupported directory
//     sync operations (e.g. EINVAL/ENOTSUP) are ignored, and any directory sync failure
//     is logged as a warning to os.Stderr rather than failing the write, as the report file is
//     already safely in place on disk.
//  4. Cleanup: Temporary files are guaranteed to be closed and removed on any failure before rename.
func WriteReport(path string, report Report) error {
	if path == "" {
		return fmt.Errorf("report path cannot be empty")
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}

	tempFile, err := os.CreateTemp(dir, "report-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temporary report file: %w", err)
	}

	tempPath := tempFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = closeFileHook(tempFile)
			_ = os.Remove(tempPath)
		}
	}()

	if err := tempFile.Chmod(0644); err != nil {
		return fmt.Errorf("chmod temporary report file: %w", err)
	}

	if _, err := tempFile.Write(data); err != nil {
		return fmt.Errorf("write temporary report: %w", err)
	}

	if err := syncFileHook(tempFile); err != nil {
		return fmt.Errorf("sync temporary report: %w", err)
	}

	if err := closeFileHook(tempFile); err != nil {
		return fmt.Errorf("close temporary report: %w", err)
	}

	if err := renameFileHook(tempPath, path); err != nil {
		return fmt.Errorf("rename temporary report to final path: %w", err)
	}

	cleanup = false

	if err := syncDirHook(dir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to sync report directory %s: %v\n", dir, err)
	}

	return nil
}
