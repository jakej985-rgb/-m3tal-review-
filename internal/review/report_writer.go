package review

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

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

	defer func() {
		tempFile.Close()
		os.Remove(tempPath) // Clean up if rename hasn't succeeded (or just cleanup in general)
	}()

	if _, err := tempFile.Write(data); err != nil {
		return fmt.Errorf("write temporary report: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close temporary report: %w", err)
	}

	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("rename temporary report to final path: %w", err)
	}

	return nil
}
