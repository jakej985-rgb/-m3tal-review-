package review

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SupportedSchemaVersions contains the schema versions recognized by m3tal-review.
// Empty string is supported for backward compatibility with unversioned reports.
var SupportedSchemaVersions = map[string]bool{
	"":      true,
	"1.0":   true,
	"1.0.0": true,
	"v1":    true,
}

var ValidSeverities = map[string]bool{
	"info":     true,
	"low":      true,
	"medium":   true,
	"high":     true,
	"critical": true,
}

var ValidCategories = map[string]bool{
	"security":   true,
	"review":     true,
	"confidence": true,
	"risk":       true,
	"drift":      true,
}

var ValidCheckStatuses = map[string]bool{
	"passed":  true,
	"failed":  true,
	"skipped": true,
	"warning": true,
	"error":   true,
	"ok":      true,
	"warn":    true,
}

type ReportValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

type ReportValidationResult struct {
	Path          string                  `json:"path"`
	RunID         string                  `json:"run_id,omitempty"`
	SchemaVersion string                  `json:"schema_version,omitempty"`
	Valid         bool                    `json:"valid"`
	FindingCount  int                     `json:"finding_count"`
	CheckCount    int                     `json:"check_count"`
	Errors        []ReportValidationError `json:"errors,omitempty"`
	Warnings      []string                `json:"warnings,omitempty"`
}

type ReportValidationSummary struct {
	Valid          bool                     `json:"valid"`
	TotalReports   int                      `json:"total_reports"`
	ValidReports   int                      `json:"valid_reports"`
	InvalidReports int                      `json:"invalid_reports"`
	Results        []ReportValidationResult `json:"results"`
}

// ValidateReport checks a Report struct and optional file path for schema and data integrity.
// It is strictly non-modifying.
func ValidateReport(report Report, filePath string) ReportValidationResult {
	res := ReportValidationResult{
		Path:          filePath,
		RunID:         report.RunID,
		SchemaVersion: report.SchemaVersion,
		FindingCount:  len(report.Findings),
		CheckCount:    len(report.Checks),
		Valid:         true,
	}

	addErr := func(field, msg string) {
		res.Valid = false
		res.Errors = append(res.Errors, ReportValidationError{Field: field, Message: msg})
	}

	// 1. Schema version check
	if !SupportedSchemaVersions[report.SchemaVersion] {
		addErr("schema_version", fmt.Sprintf("unsupported schema version %q; supported: 1.0, 1.0.0", report.SchemaVersion))
	}

	// 2. Required fields
	if report.RunID == "" {
		addErr("run_id", "run_id is required")
	} else if !IsValidRunID(report.RunID) {
		addErr("run_id", fmt.Sprintf("invalid run_id %q: must be 16 lowercase hex characters", report.RunID))
	}

	if report.Timestamp.IsZero() {
		addErr("timestamp", "timestamp is required and must not be zero")
	}

	if strings.TrimSpace(report.Repository) == "" {
		addErr("repository", "repository is required")
	}

	if strings.TrimSpace(report.Summary) == "" {
		addErr("summary", "summary is required")
	}

	if strings.TrimSpace(report.ToolVersion) == "" {
		addErr("tool_version", "tool_version is required")
	}

	// 3. Run ID / path agreement
	if filePath != "" {
		base := filepath.Base(filePath)
		if strings.HasSuffix(base, ".json") {
			candidateID := strings.TrimSuffix(base, ".json")
			if IsValidRunID(candidateID) && candidateID != report.RunID {
				addErr("run_id_path_agreement", fmt.Sprintf("filename %q indicates run_id %q but report contains %q", base, candidateID, report.RunID))
			} else if filepath.Base(filepath.Dir(filePath)) == "reports" && base != report.RunID+".json" {
				addErr("run_id_path_agreement", fmt.Sprintf("reports directory requires canonical filename <run_id>.json (%s.json), got %q", report.RunID, base))
			}
		}
	}

	// 4. Finding IDs and Finding validation
	seenFindingIDs := make(map[string]int, len(report.Findings))
	for i, f := range report.Findings {
		idxStr := fmt.Sprintf("findings[%d]", i)

		if strings.TrimSpace(f.Rule) == "" {
			addErr(idxStr+".rule", "rule cannot be empty")
		}

		if strings.TrimSpace(f.File) == "" {
			addErr(idxStr+".file", "file cannot be empty")
		}

		if f.Line < 0 {
			addErr(idxStr+".line", "line cannot be negative")
		}

		if strings.TrimSpace(f.Message) == "" {
			addErr(idxStr+".message", "message cannot be empty")
		}

		if !ValidSeverities[f.Severity] {
			addErr(idxStr+".severity", fmt.Sprintf("invalid severity %q; valid: info, low, medium, high, critical", f.Severity))
		}

		if f.Category != "" && !ValidCategories[f.Category] {
			addErr(idxStr+".category", fmt.Sprintf("invalid category %q; valid: security, review, confidence, risk, drift", f.Category))
		}

		if f.ID == "" {
			addErr(idxStr+".id", "finding id cannot be empty")
		} else {
			if len(f.ID) != 16 {
				addErr(idxStr+".id", fmt.Sprintf("invalid finding id %q: expected 16 hex characters", f.ID))
			} else if _, hexErr := hex.DecodeString(f.ID); hexErr != nil {
				addErr(idxStr+".id", fmt.Sprintf("invalid finding id %q: not valid hexadecimal", f.ID))
			}

			if prevIdx, exists := seenFindingIDs[f.ID]; exists {
				addErr(idxStr+".id", fmt.Sprintf("duplicate finding id %q (already used by finding %d)", f.ID, prevIdx))
			} else {
				seenFindingIDs[f.ID] = i
			}
		}
	}

	// 5. Check statuses validation
	for i, c := range report.Checks {
		idxStr := fmt.Sprintf("checks[%d]", i)
		if strings.TrimSpace(c.Name) == "" {
			addErr(idxStr+".name", "check name cannot be empty")
		}
		if strings.TrimSpace(c.Category) == "" {
			addErr(idxStr+".category", "check category cannot be empty")
		}
		if !ValidCheckStatuses[c.Status] {
			addErr(idxStr+".status", fmt.Sprintf("invalid check status %q; valid: passed, failed, skipped, warning, error", c.Status))
		}
	}

	return res
}

// ValidateReportFile reads and validates a single report file without modifying it.
func ValidateReportFile(path string) ReportValidationResult {
	info, err := os.Stat(path)
	if err != nil {
		return ReportValidationResult{
			Path:  path,
			Valid: false,
			Errors: []ReportValidationError{
				{Field: "file", Message: fmt.Sprintf("cannot access report file: %v", err)},
			},
		}
	}

	if info.IsDir() {
		return ReportValidationResult{
			Path:  path,
			Valid: false,
			Errors: []ReportValidationError{
				{Field: "file", Message: "specified path is a directory, not a report file"},
			},
		}
	}

	if info.Size() > 50*1024*1024 {
		return ReportValidationResult{
			Path:  path,
			Valid: false,
			Errors: []ReportValidationError{
				{Field: "file", Message: fmt.Sprintf("report exceeds size limit (50MB): %d bytes", info.Size())},
			},
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return ReportValidationResult{
			Path:  path,
			Valid: false,
			Errors: []ReportValidationError{
				{Field: "file", Message: fmt.Sprintf("failed to read file: %v", err)},
			},
		}
	}

	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return ReportValidationResult{
			Path:  path,
			Valid: false,
			Errors: []ReportValidationError{
				{Field: "schema", Message: fmt.Sprintf("invalid JSON / schema decode failed: %v", err)},
			},
		}
	}

	return ValidateReport(report, path)
}

// ValidateReportTarget validates either a single report file or a directory containing report files.
func ValidateReportTarget(targetPath string) ReportValidationSummary {
	info, err := os.Stat(targetPath)
	if err != nil {
		return ReportValidationSummary{
			Valid:          false,
			TotalReports:   1,
			ValidReports:   0,
			InvalidReports: 1,
			Results: []ReportValidationResult{
				{
					Path:  targetPath,
					Valid: false,
					Errors: []ReportValidationError{
						{Field: "path", Message: fmt.Sprintf("target path error: %v", err)},
					},
				},
			},
		}
	}

	if !info.IsDir() {
		res := ValidateReportFile(targetPath)
		summary := ReportValidationSummary{
			Valid:        res.Valid,
			TotalReports: 1,
			Results:      []ReportValidationResult{res},
		}
		if res.Valid {
			summary.ValidReports = 1
		} else {
			summary.InvalidReports = 1
		}
		return summary
	}

	// Directory target: find all .json files in target directory
	entries, err := os.ReadDir(targetPath)
	if err != nil {
		return ReportValidationSummary{
			Valid:          false,
			TotalReports:   0,
			ValidReports:   0,
			InvalidReports: 1,
			Results: []ReportValidationResult{
				{
					Path:  targetPath,
					Valid: false,
					Errors: []ReportValidationError{
						{Field: "directory", Message: fmt.Sprintf("failed to read directory: %v", err)},
					},
				},
			},
		}
	}

	var jsonFiles []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".json") && !strings.HasSuffix(entry.Name(), ".tmp") {
			jsonFiles = append(jsonFiles, filepath.Join(targetPath, entry.Name()))
		}
	}

	sort.Strings(jsonFiles)

	summary := ReportValidationSummary{
		Valid:        true,
		TotalReports: len(jsonFiles),
		Results:      make([]ReportValidationResult, 0, len(jsonFiles)),
	}

	for _, file := range jsonFiles {
		res := ValidateReportFile(file)
		summary.Results = append(summary.Results, res)
		if res.Valid {
			summary.ValidReports++
		} else {
			summary.InvalidReports++
			summary.Valid = false
		}
	}

	return summary
}
