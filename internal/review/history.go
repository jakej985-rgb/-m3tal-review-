package review

import "time"

type HistoryEntry struct {
	Scope        string    `json:"scope,omitempty"`
	RunID        string    `json:"run_id"`
	Timestamp    time.Time `json:"timestamp"`
	Status       string    `json:"status"`
	FindingCount int       `json:"finding_count"`
	Summary      string    `json:"summary"`
}

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
