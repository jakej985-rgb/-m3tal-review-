package review

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
)

const policyFileName = ".m3tal-review-policy.json"

type reviewPolicy struct {
	RiskPaths       []string                    `json:"risk_paths,omitempty"`
	ForbiddenPaths  []string                    `json:"forbidden_paths,omitempty"`
	RequireTogether []pathCoupling              `json:"require_together,omitempty"`
	Rules           map[string]policyRuleTuning `json:"rules,omitempty"`
}

// policyRuleTuning lets a repository disable a rule or override the severity
// of its findings, e.g. {"rules": {"code-slop": {"severity": "info"}}}.
type policyRuleTuning struct {
	Enabled  *bool  `json:"enabled,omitempty"`
	Severity string `json:"severity,omitempty"`
}

type pathCoupling struct {
	WhenChanged string   `json:"when_changed"`
	AlsoChange  []string `json:"also_change"`
}

type RiskRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (RiskRule) Name() string { return "review-risk" }

func (r RiskRule) Check(diff string) []Finding {
	policy, err := readReviewPolicy(r.RepositoryRoot, r.WorkingTree)
	if err != nil {
		return nil // PolicyRule reports the configuration failure once.
	}
	var findings []Finding
	for _, file := range ParseDiff(diff) {
		for _, pattern := range policy.RiskPaths {
			if matchesRepoPath(pattern, file.Path) {
				findings = append(findings, Finding{
					Category: "risk", Rule: "review-risk", Severity: "info", File: file.Path,
					Message:     "Changed path matches a configured high-risk area: " + pattern,
					Remediation: "Review this change with the project’s security and release requirements in mind.",
				})
				break
			}
		}
	}
	return findings
}

type PolicyRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (PolicyRule) Name() string { return "review-policy" }

func (r PolicyRule) Check(diff string) []Finding {
	policy, err := readReviewPolicy(r.RepositoryRoot, r.WorkingTree)
	if err != nil {
		return policyErrorFinding(err)
	}
	files := ParseDiff(diff)
	changed := make([]string, 0, len(files))
	for _, file := range files {
		changed = append(changed, file.Path)
	}
	sort.Strings(changed)
	var findings []Finding
	for _, file := range changed {
		for _, pattern := range policy.ForbiddenPaths {
			if matchesRepoPath(pattern, file) {
				findings = append(findings, Finding{
					Category: "drift", Rule: "review-policy", Severity: "medium", File: file,
					Message:     "Changed path is forbidden by project review policy: " + pattern,
					Remediation: "Move the change to an approved path or update the project policy through review.",
				})
			}
		}
	}
	for _, coupling := range policy.RequireTogether {
		triggered := false
		for _, file := range changed {
			if matchesRepoPath(coupling.WhenChanged, file) {
				triggered = true
				break
			}
		}
		if !triggered {
			continue
		}
		for _, required := range coupling.AlsoChange {
			present := false
			for _, file := range changed {
				if matchesRepoPath(required, file) {
					present = true
					break
				}
			}
			if !present {
				findings = append(findings, Finding{
					Category: "drift", Rule: "review-policy", Severity: "medium",
					Message:     fmt.Sprintf("Policy requires a change matching %q when %q changes", required, coupling.WhenChanged),
					Remediation: "Include the coupled project changes or revise the policy with an approved exception.",
				})
			}
		}
	}
	return findings
}

func readReviewPolicy(repositoryRoot string, workingTree bool) (reviewPolicy, error) {
	if repositoryRoot == "" {
		return reviewPolicy{}, nil
	}
	file := path.Join(repositoryRoot, policyFileName)
	// The policy file is repo-controlled input; refuse to follow a symlink
	// that could redirect the read outside the repository.
	if info, statErr := os.Lstat(file); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return reviewPolicy{}, fmt.Errorf("%s must not be a symbolic link", policyFileName)
	}
	var data []byte
	var err error
	if workingTree {
		data, err = os.ReadFile(file)
	} else {
		data, err = git.StagedFileContent(repositoryRoot, policyFileName)
		if err != nil {
			// A local policy can intentionally govern reviews without being staged.
			data, err = os.ReadFile(file)
		}
	}
	if os.IsNotExist(err) {
		return reviewPolicy{}, nil
	}
	if err != nil {
		return reviewPolicy{}, fmt.Errorf("read %s: %w", policyFileName, err)
	}
	var policy reviewPolicy
	decoderErr := json.Unmarshal(data, &policy)
	if decoderErr != nil {
		return reviewPolicy{}, fmt.Errorf("decode %s: %w", policyFileName, decoderErr)
	}
	for _, pattern := range policy.patterns() {
		if pattern == "" {
			return reviewPolicy{}, fmt.Errorf("empty path pattern in %s", policyFileName)
		}
		for _, segment := range strings.Split(pattern, "/") {
			if segment == "**" {
				continue
			}
			if _, err := path.Match(segment, "validation"); err != nil {
				return reviewPolicy{}, fmt.Errorf("invalid path pattern %q in %s: %w", pattern, policyFileName, err)
			}
		}
	}
	for _, coupling := range policy.RequireTogether {
		if len(coupling.AlsoChange) == 0 {
			return reviewPolicy{}, fmt.Errorf("require_together entry for %q has no also_change patterns", coupling.WhenChanged)
		}
	}
	return policy, nil
}

func (p reviewPolicy) patterns() []string {
	patterns := append([]string{}, p.RiskPaths...)
	patterns = append(patterns, p.ForbiddenPaths...)
	for _, coupling := range p.RequireTogether {
		patterns = append(patterns, coupling.WhenChanged)
		patterns = append(patterns, coupling.AlsoChange...)
	}
	return patterns
}

// matchMemo bounds the recursive glob matcher. Policy files are repo-controlled
// input, so patterns like "**/**/**" against deep paths could otherwise cause
// combinatorial backtracking.
type matchMemo map[[2]int]bool

func (m matchMemo) match(patternParts, fileParts []string, pi, fi int) bool {
	key := [2]int{pi, fi}
	if result, ok := m[key]; ok {
		return result
	}
	result := m.matchUncached(patternParts, fileParts, pi, fi)
	m[key] = result
	return result
}

func (m matchMemo) matchUncached(patternParts, fileParts []string, pi, fi int) bool {
	if pi == len(patternParts) {
		return fi == len(fileParts)
	}
	if patternParts[pi] == "**" {
		for next := fi; next <= len(fileParts); next++ {
			if m.match(patternParts, fileParts, pi+1, next) {
				return true
			}
		}
		return false
	}
	if fi == len(fileParts) {
		return false
	}
	matched, err := path.Match(patternParts[pi], fileParts[fi])
	return err == nil && matched && m.match(patternParts, fileParts, pi+1, fi+1)
}

func matchesRepoPath(pattern, file string) bool {
	patternParts := strings.Split(pattern, "/")
	fileParts := strings.Split(file, "/")
	return matchMemo{}.match(patternParts, fileParts, 0, 0)
}

func policyErrorFinding(err error) []Finding {
	return []Finding{{
		Category: "confidence", Rule: "review-policy-config-error", Severity: "high", File: policyFileName,
		Message:     "Project review policy could not be loaded: " + err.Error(),
		Remediation: "Fix the JSON policy file or remove it, then rerun the review.",
	}}
}

var _ Rule = RiskRule{}
var _ Rule = PolicyRule{}
