package review

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// ScopeExclusion records a path or category of paths excluded from analysis.
type ScopeExclusion struct {
	Reason string   `json:"reason"`
	Count  int      `json:"count"`
	Paths  []string `json:"paths,omitempty"`
}

// CoverageMetadata documents first-party vs third-party dependency scope and exclusions.
type CoverageMetadata struct {
	TotalFiles      int              `json:"total_files"`
	FirstPartyFiles int              `json:"first_party_files"`
	VendorFiles     int              `json:"vendor_files"`
	UnanalyzedFiles int              `json:"unanalyzed_files"`
	Complete        bool             `json:"complete"`
	Exclusions      []ScopeExclusion `json:"exclusions,omitempty"`
}

// IsVendorOrDependencyPath returns true for common third-party dependency and generated paths.
func IsVendorOrDependencyPath(path string) bool {
	normalized := filepath.ToSlash(path)
	parts := strings.Split(normalized, "/")
	for _, part := range parts {
		switch part {
		case "node_modules", "vendor", ".bundle", "dist", "build", ".next", ".nuxt", "bower_components":
			return true
		}
	}
	return false
}

// ReportAttestation provides a tamper-evident digest of review execution inputs and verdict.
type ReportAttestation struct {
	Version      string    `json:"version"`
	Repository   string    `json:"repository"`
	CommitSHA    string    `json:"commit_sha"`
	DiffHash     string    `json:"diff_hash"`
	SnapshotHash string    `json:"snapshot_hash,omitempty"`
	ToolVersion  string    `json:"tool_version"`
	Timestamp    time.Time `json:"timestamp"`
	Passed       bool      `json:"passed"`
	Signature    string    `json:"signature"`
}

const AttestationVersion = "m3tal-attestation/v1"

// ValidateCommitSHA enforces exact 40-character hex SHA requirements, rejecting abbreviated prefixes.
func ValidateCommitSHA(sha string) error {
	if sha == "" {
		return fmt.Errorf("missing commit SHA: exact 40-character full commit SHA is required")
	}
	if len(sha) != 40 {
		return fmt.Errorf("invalid commit SHA %q: expected full 40-character hex SHA (got %d chars); abbreviated prefixes are rejected", sha, len(sha))
	}
	for _, c := range sha {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return fmt.Errorf("invalid commit SHA %q: contains non-hex characters", sha)
		}
	}
	return nil
}

// ComputeAttestationSignature calculates the canonical SHA-256 integrity signature.
func ComputeAttestationSignature(version, repository, commitSHA, diffHash, snapshotHash, toolVersion string, timestampUnix int64, passed bool) string {
	payload := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%d\n%t",
		version,
		repository,
		strings.ToLower(commitSHA),
		diffHash,
		snapshotHash,
		toolVersion,
		timestampUnix,
		passed,
	)
	hash := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(hash[:])
}

// GenerateAttestation creates a signed ReportAttestation for a review Report.
func GenerateAttestation(report *Report, snapshotHash string) (ReportAttestation, error) {
	if err := ValidateCommitSHA(report.CommitSHA); err != nil {
		return ReportAttestation{}, err
	}
	ts := report.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	sig := ComputeAttestationSignature(
		AttestationVersion,
		report.Repository,
		report.CommitSHA,
		report.DiffHash,
		snapshotHash,
		report.ToolVersion,
		ts.Unix(),
		report.Passed,
	)
	return ReportAttestation{
		Version:      AttestationVersion,
		Repository:   report.Repository,
		CommitSHA:    strings.ToLower(report.CommitSHA),
		DiffHash:     report.DiffHash,
		SnapshotHash: snapshotHash,
		ToolVersion:  report.ToolVersion,
		Timestamp:    ts,
		Passed:       report.Passed,
		Signature:    sig,
	}, nil
}

// VerifyAttestation validates report integrity, commit SHA exactness, repository match, and freshness.
func VerifyAttestation(report Report, expectedRepo, expectedCommitSHA, expectedDiffHash, expectedSnapshotHash string, maxAge time.Duration) error {
	if report.Attestation == nil {
		return fmt.Errorf("missing attestation: report has not been signed or verified")
	}
	att := report.Attestation
	if att.Version != AttestationVersion {
		return fmt.Errorf("unsupported attestation version %q; expected %q", att.Version, AttestationVersion)
	}

	if err := ValidateCommitSHA(expectedCommitSHA); err != nil {
		return fmt.Errorf("target commit validation failed: %w", err)
	}
	if err := ValidateCommitSHA(att.CommitSHA); err != nil {
		return fmt.Errorf("report attestation commit validation failed: %w", err)
	}

	normExpectedSHA := strings.ToLower(expectedCommitSHA)
	normAttSHA := strings.ToLower(att.CommitSHA)
	if normAttSHA != normExpectedSHA {
		return fmt.Errorf("commit SHA mismatch: report attestation (%s) does not match target commit (%s)", normAttSHA, normExpectedSHA)
	}
	if strings.ToLower(report.CommitSHA) != normExpectedSHA {
		return fmt.Errorf("report commit SHA mismatch: report body (%s) does not match target commit (%s)", report.CommitSHA, normExpectedSHA)
	}

	if expectedRepo != "" {
		if att.Repository != expectedRepo {
			return fmt.Errorf("repository mismatch: report attestation repository (%q) does not match expected (%q)", att.Repository, expectedRepo)
		}
		if report.Repository != expectedRepo {
			return fmt.Errorf("repository mismatch: report body repository (%q) does not match expected (%q)", report.Repository, expectedRepo)
		}
	}

	if expectedDiffHash != "" && att.DiffHash != expectedDiffHash {
		return fmt.Errorf("diff hash mismatch: attestation diff (%s) does not match expected (%s)", att.DiffHash, expectedDiffHash)
	}

	if expectedSnapshotHash != "" && att.SnapshotHash != expectedSnapshotHash {
		return fmt.Errorf("snapshot hash mismatch: attestation snapshot (%s) does not match expected (%s)", att.SnapshotHash, expectedSnapshotHash)
	}

	if maxAge > 0 && time.Since(att.Timestamp) > maxAge {
		return fmt.Errorf("attestation is stale: generated at %s (%s ago, max allowed %s)", att.Timestamp.Format(time.RFC3339), time.Since(att.Timestamp).Truncate(time.Second), maxAge)
	}

	expectedSig := ComputeAttestationSignature(
		att.Version,
		att.Repository,
		att.CommitSHA,
		att.DiffHash,
		att.SnapshotHash,
		att.ToolVersion,
		att.Timestamp.Unix(),
		att.Passed,
	)
	if !hmac.Equal([]byte(att.Signature), []byte(expectedSig)) {
		return fmt.Errorf("attestation signature invalid: report or attestation payload has been tampered with")
	}

	if att.Passed != report.Passed {
		return fmt.Errorf("attestation verdict mismatch: attestation passed=%t but report passed=%t", att.Passed, report.Passed)
	}

	return nil
}

// RemediationVerificationResult records the outcome of re-running checks on repaired code.
type RemediationVerificationResult struct {
	FindingID         string    `json:"finding_id"`
	OriginalRule      string    `json:"original_rule"`
	OriginalFile      string    `json:"original_file"`
	Status            string    `json:"status"` // "fixed", "unfixed", "new_blocking_findings", "regression_failure", "unresolved"
	Explanation       string    `json:"explanation"`
	RemainingFindings []Finding `json:"remaining_findings,omitempty"`
}

// VerifyRemediation re-runs originating rule and test suites against the repaired snapshot.
func VerifyRemediation(originalFinding Finding, originalDiff, repairedDiff string, rules []Rule, testRunner func() error) RemediationVerificationResult {
	res := RemediationVerificationResult{
		FindingID:    originalFinding.ID,
		OriginalRule: originalFinding.Rule,
		OriginalFile: originalFinding.File,
	}

	if originalDiff == repairedDiff {
		res.Status = "unfixed"
		res.Explanation = "repaired diff is identical to original diff; defect was not modified"
		return res
	}

	var originatingRule Rule
	for _, r := range rules {
		if r.Name() == originalFinding.Rule {
			originatingRule = r
			break
		}
	}

	if originatingRule != nil {
		postCheckFindings := originatingRule.Check(repairedDiff)
		for _, f := range postCheckFindings {
			if f.Rule == originalFinding.Rule && f.File == originalFinding.File {
				res.Status = "unfixed"
				res.Explanation = fmt.Sprintf("originating rule %q still detected finding on line %d of %s", f.Rule, f.Line, f.File)
				res.RemainingFindings = postCheckFindings
				return res
			}
		}
	}

	// Check if new blocking findings were introduced by the repair
	engine := NewEngine(rules...)
	originalSet := make(map[string]bool)
	for _, f := range engine.Run(originalDiff) {
		originalSet[FindingID(f)] = true
	}

	newFindings := engine.Run(repairedDiff)
	for _, nf := range newFindings {
		if !originalSet[FindingID(nf)] && (nf.Severity == "high" || nf.Severity == "critical" || nf.Severity == "medium") {
			res.Status = "new_blocking_findings"
			res.Explanation = fmt.Sprintf("repair introduced new blocking finding: %s (%s) at %s:%d", nf.Rule, nf.Severity, nf.File, nf.Line)
			res.RemainingFindings = newFindings
			return res
		}
	}

	// Run regression test suite if provided
	if testRunner != nil {
		if err := testRunner(); err != nil {
			res.Status = "regression_failure"
			res.Explanation = fmt.Sprintf("project test runner failed on repaired code: %v", err)
			return res
		}
	}

	res.Status = "fixed"
	res.Explanation = "originating finding resolved with no new blocking defects and passing tests"
	return res
}

// VerdictType enumerates allowed judge verdict statuses.
type VerdictType string

const (
	VerdictConfirmed     VerdictType = "Confirmed"
	VerdictDismissed     VerdictType = "Dismissed"
	VerdictNeedsEvidence VerdictType = "Needs Evidence"
)

// JudgeVerdict represents an evaluation decision on a specific finding.
type JudgeVerdict struct {
	FindingID string      `json:"finding_id"`
	Rule      string      `json:"rule"`
	File      string      `json:"file"`
	Line      int         `json:"line"`
	Category  string      `json:"category"`
	Verdict   VerdictType `json:"verdict"`
	Rationale string      `json:"rationale"`
	Evidence  string      `json:"evidence,omitempty"`
}

// VerdictValidationResult summarizes results of evaluating verdicts against session findings.
type VerdictValidationResult struct {
	Valid          bool     `json:"valid"`
	ValidatedCount int      `json:"validated_count"`
	RejectedCount  int      `json:"rejected_count"`
	Errors         []string `json:"errors,omitempty"`
}

// ValidateVerdict verifies that a judge verdict accurately references an existing finding with adequate evidence.
func ValidateVerdict(verdict JudgeVerdict, sessionFindings []Finding, seenFindingIDs map[string]bool) error {
	if verdict.FindingID == "" {
		return fmt.Errorf("verdict missing finding_id")
	}
	if seenFindingIDs[verdict.FindingID] {
		return fmt.Errorf("duplicate verdict for finding ID %q", verdict.FindingID)
	}

	var target *Finding
	for i := range sessionFindings {
		f := &sessionFindings[i]
		id := f.ID
		if id == "" {
			id = FindingID(*f)
		}
		if id == verdict.FindingID {
			target = f
			break
		}
	}

	if target == nil {
		return fmt.Errorf("orphaned/unknown finding ID %q: not present in current review session", verdict.FindingID)
	}

	if verdict.Rule != "" && target.Rule != verdict.Rule {
		return fmt.Errorf("mutated verdict: rule %q does not match session finding rule %q", verdict.Rule, target.Rule)
	}
	if verdict.File != "" && target.File != verdict.File {
		return fmt.Errorf("mutated verdict: file %q does not match session finding file %q", verdict.File, target.File)
	}
	if verdict.Line != 0 && target.Line != verdict.Line {
		return fmt.Errorf("mutated verdict: line %d does not match session finding line %d", verdict.Line, target.Line)
	}

	switch verdict.Verdict {
	case VerdictConfirmed:
		if strings.TrimSpace(verdict.Evidence) == "" {
			return fmt.Errorf("confirmed verdict for %q requires concrete evidence/provenance", verdict.FindingID)
		}
		if strings.TrimSpace(verdict.Rationale) == "" {
			return fmt.Errorf("confirmed verdict for %q requires explanatory rationale", verdict.FindingID)
		}
	case VerdictDismissed:
		if strings.TrimSpace(verdict.Rationale) == "" {
			return fmt.Errorf("dismissed verdict for %q requires dismissal rationale", verdict.FindingID)
		}
	case VerdictNeedsEvidence:
		// Needs Evidence preserves unresolved status
		if strings.TrimSpace(verdict.Rationale) == "" {
			return fmt.Errorf("needs-evidence verdict for %q requires rationale explaining what evidence is missing", verdict.FindingID)
		}
	default:
		return fmt.Errorf("unrecognized verdict type %q; expected Confirmed, Dismissed, or Needs Evidence", verdict.Verdict)
	}

	seenFindingIDs[verdict.FindingID] = true
	return nil
}

// ValidateVerdicts batch validates a collection of judge verdicts against session findings.
func ValidateVerdicts(verdicts []JudgeVerdict, sessionFindings []Finding) VerdictValidationResult {
	result := VerdictValidationResult{
		Valid: true,
	}
	seen := make(map[string]bool, len(verdicts))
	for _, v := range verdicts {
		if err := ValidateVerdict(v, sessionFindings, seen); err != nil {
			result.Valid = false
			result.RejectedCount++
			result.Errors = append(result.Errors, err.Error())
		} else {
			result.ValidatedCount++
		}
	}
	return result
}
