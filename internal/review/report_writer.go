package review

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// WriteReport writes a review report atomically to the specified path.
//
// Durability & Atomicity Guarantees:
//  1. File payload durability is guaranteed via fsync (syncFileHook) before closing and renaming.
//  2. Atomicity is achieved by writing to a temporary file in the target directory and moving it
//     into place using atomic rename.
//  3. Directory entry durability is ensured via syncDirHook on the parent directory following rename.
//     Unsupported directory fsync errors (EINVAL/ENOTSUP) are safely ignored; genuine I/O failures are surfaced.
//  4. Temporary files are guaranteed to be cleaned up on any write, sync, close, or rename failure.
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
		return fmt.Errorf("sync report directory: %w", err)
	}

	return nil
}
