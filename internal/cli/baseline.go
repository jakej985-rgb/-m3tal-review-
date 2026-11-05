package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// loadBaseline reads a baseline file of finding fingerprints. Accepts either
// a JSON array of strings or one fingerprint per line.
func loadBaseline(path string) (map[string]bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("baseline %q must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("baseline %q is not a regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	if len(data) > 8<<20 {
		return nil, fmt.Errorf("baseline file exceeds 8 MiB")
	}
	set := make(map[string]bool)
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return set, nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var ids []string
		if err := json.Unmarshal(data, &ids); err != nil {
			return nil, fmt.Errorf("baseline is not a JSON array of fingerprints: %w", err)
		}
		for _, id := range ids {
			set[id] = true
		}
		return set, nil
	}
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			set[line] = true
		}
	}
	return set, nil
}

// filterBaseline drops findings whose fingerprint ID appears in the baseline.
func filterBaseline(findings []review.Finding, baseline map[string]bool) []review.Finding {
	if len(baseline) == 0 {
		return findings
	}
	out := findings[:0]
	for _, f := range findings {
		if f.ID != "" && baseline[f.ID] {
			continue
		}
		out = append(out, f)
	}
	return out
}

// writeBaseline writes finding fingerprint IDs to path (JSON array).
func writeBaseline(path string, findings []review.Finding) error {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.ID != "" {
			ids = append(ids, f.ID)
		}
	}
	data, err := json.MarshalIndent(ids, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
