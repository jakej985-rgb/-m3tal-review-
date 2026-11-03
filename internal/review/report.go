package review

import "time"

type Report struct {
	Scope           string    `json:"scope,omitempty"`
	RunID           string    `json:"run_id"`
	Timestamp       time.Time `json:"timestamp"`
	Repository      string    `json:"repository"`
	Branch          string    `json:"branch"`
	CommitSHA       string    `json:"commit_sha"`
	BaseCommitSHA   string    `json:"base_commit_sha"`
	DiffHash        string    `json:"diff_hash"`
	ToolVersion     string    `json:"tool_version"`
	ReviewedFiles   []string  `json:"reviewed_files"`
	UnanalyzedFiles []string  `json:"unanalyzed_files,omitempty"`
	Passed          bool      `json:"passed"`
	Summary         string    `json:"summary"`
	Findings        []Finding `json:"findings"`
}

func NewReport(
	runID string,
	repository string,
	branch string,
	commitSHA string,
	baseCommitSHA string,
	diffHash string,
	toolVersion string,
	reviewedFiles []string,
	findings []Finding,
) Report {
	passed := len(findings) == 0

	summary := "Review passed. No findings."
	if !passed {
		summary = "Review failed. Findings require attention."
	}

	return Report{
		Scope:         "staged",
		RunID:         runID,
		Timestamp:     time.Now().UTC(),
		Repository:    repository,
		Branch:        branch,
		CommitSHA:     commitSHA,
		BaseCommitSHA: baseCommitSHA,
		DiffHash:      diffHash,
		ToolVersion:   toolVersion,
		ReviewedFiles: reviewedFiles,
		Passed:        passed,
		Summary:       summary,
		Findings:      findings,
	}
}
