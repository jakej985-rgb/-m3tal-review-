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

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	return nil
}
