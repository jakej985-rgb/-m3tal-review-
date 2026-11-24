package review

import "github.com/jakej985-rgb/m3tal-review/internal/review/history"

// HistoryEntry is the JSONL history record owned by internal/review/history.
type HistoryEntry = history.HistoryEntry

func NewHistoryEntry(report Report) HistoryEntry {
	status := "passed"

	if !report.Passed {
		status = "failed"
	}
	if len(report.UnanalyzedFiles) > 0 {
		status = "incomplete"
	}

	return HistoryEntry{
		Scope:        report.Scope,
		RunID:        report.RunID,
		Timestamp:    report.Timestamp,
		Status:       status,
		FindingCount: len(report.Findings),
		Summary:      report.Summary,
	}
}
