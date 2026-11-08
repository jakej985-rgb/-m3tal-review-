package review

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

type CheckResult struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Status   string `json:"status"`
	Message  string `json:"message,omitempty"`
}

type FindingChanges struct {
	New      []string `json:"new,omitempty"`
	Resolved []string `json:"resolved,omitempty"`
	Existing int      `json:"existing"`
}

type Report struct {
	Scope           string             `json:"scope,omitempty"`
	Profile         string             `json:"profile,omitempty"`
	RunID           string             `json:"run_id"`
	Timestamp       time.Time          `json:"timestamp"`
	Repository      string             `json:"repository"`
	Branch          string             `json:"branch"`
	CommitSHA       string             `json:"commit_sha"`
	BaseCommitSHA   string             `json:"base_commit_sha"`
	DiffHash        string             `json:"diff_hash"`
	ToolVersion     string             `json:"tool_version"`
	ReviewedFiles   []string           `json:"reviewed_files"`
	UnanalyzedFiles []string           `json:"unanalyzed_files,omitempty"`
	Passed          bool               `json:"passed"`
	Summary         string             `json:"summary"`
	Findings        []Finding          `json:"findings"`
	Checks          []CheckResult      `json:"checks,omitempty"`
	FindingChanges  *FindingChanges    `json:"finding_changes,omitempty"`
	Coverage        *CoverageMetadata  `json:"coverage,omitempty"`
	Attestation     *ReportAttestation `json:"attestation,omitempty"`
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
	findings = append([]Finding(nil), findings...)
	passed := true
	for i := range findings {
		if findings[i].Category == "" {
			findings[i].Category = categoryForRule(findings[i].Rule)
		}
		if findings[i].ID == "" {
			findings[i].ID = FindingID(findings[i])
		}
		finding := findings[i]
		if finding.Severity != "info" {
			passed = false
			break
		}
	}

	summary := "Review passed. No findings."
	if !passed {
		summary = "Review failed. Findings require attention."
	} else if len(findings) > 0 {
		summary = "Review passed with informational risk signals."
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

// FindingID returns a stable identifier for the same rule, file, line, and
// message. Reports can use it to compare repeated reviews without an agent.
func FindingID(f Finding) string {
	category := f.Category
	if category == "" {
		category = categoryForRule(f.Rule)
	}
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s", category, f.Rule, f.File, f.Line, f.Message)
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:8])
}

func CompareFindings(previous, current []Finding) FindingChanges {
	previousIDs := make(map[string]bool, len(previous))
	currentIDs := make(map[string]bool, len(current))
	for _, finding := range previous {
		id := finding.ID
		if id == "" {
			id = FindingID(finding)
		}
		previousIDs[id] = true
	}
	for _, finding := range current {
		id := finding.ID
		if id == "" {
			id = FindingID(finding)
		}
		currentIDs[id] = true
	}
	var changes FindingChanges
	for id := range currentIDs {
		if previousIDs[id] {
			changes.Existing++
		} else {
			changes.New = append(changes.New, id)
		}
	}
	for id := range previousIDs {
		if !currentIDs[id] {
			changes.Resolved = append(changes.Resolved, id)
		}
	}
	sort.Strings(changes.New)
	sort.Strings(changes.Resolved)
	return changes
}
