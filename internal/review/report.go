package review

import "time"

type Report struct {
	RunID      string    `json:"run_id"`
	Timestamp  time.Time `json:"timestamp"`
	Repository string    `json:"repository"`
	Branch     string    `json:"branch"`
	Passed     bool      `json:"passed"`
	Summary    string    `json:"summary"`
	Findings   []Finding `json:"findings"`
}

func NewReport(
	runID string,
	repository string,
	branch string,
	findings []Finding,
) Report {
	passed := len(findings) == 0

	summary := "Review passed. No findings."
	if !passed {
		summary = "Review failed. Findings require attention."
	}

	return Report{
		RunID:      runID,
		Timestamp:  time.Now().UTC(),
		Repository: repository,
		Branch:     branch,
		Passed:     passed,
		Summary:    summary,
		Findings:   findings,
	}
}
