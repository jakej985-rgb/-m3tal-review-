package review

import (
	"sort"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
)

type CheckResult struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Status   string `json:"status"`
	Message  string `json:"message,omitempty"`
	Version  string `json:"version,omitempty"`
	Path     string `json:"path,omitempty"`
}

type FindingChanges struct {
	New      []string `json:"new,omitempty"`
	Resolved []string `json:"resolved,omitempty"`
	Existing int      `json:"existing"`
}

// AnalysisProgramSummary describes the shared semantic program a
// pipeline run analyzed.
type AnalysisProgramSummary struct {
	Packages  int    `json:"packages"`
	Functions int    `json:"functions"`
	Values    int    `json:"values"`
	RootDir   string `json:"root_dir,omitempty"`
}

// AnalysisSection separates semantic-engine output from the
// pattern/inventory tier: per-analyzer check results, the shared
// program summary, and the merged analysis diagnostics (load
// problems, unsupported constructs, budget exhaustion). Findings
// themselves flow through Report.Findings with Category "semantic".
type AnalysisSection struct {
	// Status is "completed", "degraded" (partial analysis: analyzer
	// failures, truncation, or error diagnostics), or "failed" (the
	// shared frontend could not load a program at all).
	Status    string                  `json:"status"`
	LoadError string                  `json:"load_error,omitempty"`
	Program   *AnalysisProgramSummary `json:"program,omitempty"`
	Analyzers []CheckResult           `json:"analyzers,omitempty"`
	// Diagnostics are the merged analysis-contract diagnostics,
	// deterministically sorted.
	Diagnostics []analysis.Diagnostic `json:"diagnostics,omitempty"`
	Truncated   bool                  `json:"truncated,omitempty"`
}

// CurrentReportSchemaVersion specifies the active schema version produced by m3tal-review.
const CurrentReportSchemaVersion = "1.0.0"

type Report struct {
	SchemaVersion   string             `json:"schema_version,omitempty"`
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
	// Analysis is present only when the semantic pipeline ran; it
	// separates semantic-engine diagnostics and per-analyzer status
	// from the pattern-tier findings.
	Analysis *AnalysisSection `json:"analysis,omitempty"`
	// Apps records per-language-app execution metadata when --apps is used.
	Apps []AppRun `json:"apps,omitempty"`
	// Grade holds the deterministic quality score (0–100) and letter
	// grade (A–F) computed from findings. Always present.
	Grade *GradeResult `json:"grade,omitempty"`
}

// AppRun records execution telemetry for a single language app in a run.
type AppRun struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Status     string `json:"status"`
	ExitCode   int    `json:"exit_code"`
	DurationMs int64  `json:"duration_ms"`
	Files      int    `json:"files"`
	Rules      int    `json:"rules"`
	Findings   int    `json:"findings"`
	Error      string `json:"error,omitempty"`
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
	findings = PrioritizeFindings(AssignFindingIDs(findings))
	passed := true
	for i := range findings {
		if findings[i].Category == "" {
			findings[i].Category = categoryForRule(findings[i].Rule)
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

	grade := ComputeGrade(findings)
	return Report{
		SchemaVersion: CurrentReportSchemaVersion,
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
		Grade:         &grade,
	}
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
