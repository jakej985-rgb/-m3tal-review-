package repair

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// ApprovalHandler determines whether a verified proposal should be applied to the real repository.
type ApprovalHandler func(proposal *Proposal, verification review.RemediationVerificationResult) (bool, error)

// RepairEngine coordinates the isolated generation, validation, and remediation of code findings.
type RepairEngine struct {
	RepoRoot          string
	Fixers            []Fixer
	Rules             []review.Rule
	MaxAttempts       int
	AuditPath         string
	PreferWorktree    bool
	DryRun            bool
	TestRunnerFactory func(sandboxDir string) func() error
	ApprovalHandler   ApprovalHandler
}

// RepairResult encapsulates the result of a repair execution for a finding.
type RepairResult struct {
	Finding    review.Finding                       `json:"finding"`
	Proposal   *Proposal                            `json:"proposal,omitempty"`
	Attempts   int                                  `json:"attempts"`
	Validation review.RemediationVerificationResult `json:"validation"`
	Outcome    RepairOutcome                        `json:"outcome"`
	Applied    bool                                 `json:"applied"`
	AuditPath  string                               `json:"audit_path"`
	Error      error                                `json:"error,omitempty"`
}

// NewRepairEngine constructs a RepairEngine with canonical defaults.
func NewRepairEngine(repoRoot string, rules []review.Rule) *RepairEngine {
	return &RepairEngine{
		RepoRoot:       repoRoot,
		Fixers:         AllowlistedFixers(),
		Rules:          rules,
		MaxAttempts:    3,
		AuditPath:      filepath.Join(repoRoot, ".m3tal-review", "repairs.jsonl"),
		PreferWorktree: false,
	}
}

// RepairFinding executes the constrained, isolated repair workflow for a single finding.
func (e *RepairEngine) RepairFinding(ctx context.Context, finding review.Finding) (*RepairResult, error) {
	auditPath := e.AuditPath
	if auditPath == "" {
		auditPath = filepath.Join(e.RepoRoot, ".m3tal-review", "repairs.jsonl")
	}

	result := &RepairResult{
		Finding:   finding,
		AuditPath: auditPath,
	}

	// 1. Check fixer eligibility
	fixer := FindFixerForFinding(finding)
	if fixer == nil {
		result.Outcome = OutcomeNoFixer
		entry := RepairAuditEntry{
			RepairID:        fmt.Sprintf("rep-%d", time.Now().UnixNano()),
			Timestamp:       time.Now().UTC(),
			OriginalFinding: finding,
			Outcome:         OutcomeNoFixer,
			Attempts:        0,
			Error:           "no allowlisted deterministic fixer eligible for finding",
		}
		_ = AppendRepairAudit(auditPath, entry)
		return result, nil
	}

	maxAttempts := e.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 3
	}

	var finalProposal *Proposal
	var finalVerification review.RemediationVerificationResult
	var validationLogs strings.Builder
	var lastErr error
	attempts := 0
	verifiedFixed := false

	repairID := fmt.Sprintf("rep-%d", time.Now().UnixNano())

	// Ensure target file path is safe before reading
	if err := ValidateTargetFilePath(e.RepoRoot, finding.File); err != nil {
		result.Outcome = OutcomeVerificationFailed
		result.Error = err
		entry := RepairAuditEntry{
			RepairID:        repairID,
			Timestamp:       time.Now().UTC(),
			OriginalFinding: finding,
			FixerName:       fixer.Name(),
			TargetFile:      finding.File,
			Outcome:         OutcomeVerificationFailed,
			Attempts:        1,
			Error:           err.Error(),
		}
		_ = AppendRepairAudit(auditPath, entry)
		return result, nil
	}

	targetPath := filepath.Join(e.RepoRoot, finding.File)
	baseContent, err := os.ReadFile(targetPath)
	if err != nil {
		result.Outcome = OutcomeVerificationFailed
		result.Error = err
		entry := RepairAuditEntry{
			RepairID:        repairID,
			Timestamp:       time.Now().UTC(),
			OriginalFinding: finding,
			FixerName:       fixer.Name(),
			TargetFile:      finding.File,
			Outcome:         OutcomeVerificationFailed,
			Attempts:        1,
			Error:           err.Error(),
		}
		_ = AppendRepairAudit(auditPath, entry)
		return result, nil
	}

	currentContent := string(baseContent)
	currentFinding := finding

	// 2. Bounded attempt loop
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		attempts++

		// Generate proposal based on candidate content
		prop, err := fixer.GenerateProposal(ctx, e.RepoRoot, currentFinding, []byte(currentContent))
		if err != nil {
			lastErr = err
			validationLogs.WriteString(fmt.Sprintf("Attempt %d: fixer %s failed: %v\n", attempt, fixer.Name(), err))
			break
		}
		if prop == nil {
			validationLogs.WriteString(fmt.Sprintf("Attempt %d: fixer %s produced no changes\n", attempt, fixer.Name()))
			break
		}

		// Ensure proposal diff is always canonical against repository baseline
		prop = NewProposal(
			fmt.Sprintf("%s-%d", repairID, attempt),
			finding,
			fixer.Name(),
			finding.File,
			string(baseContent),
			prop.ProposedContent,
			prop.Explanation,
		)
		finalProposal = prop

		// Validate patch boundaries
		if err := ValidatePatchBoundaries(e.RepoRoot, prop.TargetFile, prop.Patch); err != nil {
			lastErr = err
			validationLogs.WriteString(fmt.Sprintf("Attempt %d: patch boundary validation failed: %v\n", attempt, err))
			break // Security violation, abort immediately
		}

		// Create isolated temporary sandbox
		sb, err := NewSandbox(e.RepoRoot, e.PreferWorktree)
		if err != nil {
			lastErr = err
			validationLogs.WriteString(fmt.Sprintf("Attempt %d: sandbox creation failed: %v\n", attempt, err))
			break
		}

		// Run isolated verification within sandbox with guaranteed cleanup
		func() {
			defer func() {
				if err := sb.Close(); err != nil {
					validationLogs.WriteString(fmt.Sprintf("Attempt %d: sandbox cleanup warning: %v\n", attempt, err))
				}
			}()

			// Apply proposal inside sandbox
			if err := sb.ApplyProposal(prop); err != nil {
				lastErr = err
				validationLogs.WriteString(fmt.Sprintf("Attempt %d: apply proposal in sandbox: %v\n", attempt, err))
				return
			}

			// Generate diffs representing original defect vs repaired snapshot
			origDiff := FileToAddedDiff(prop.TargetFile, prop.OriginalContent)
			repairedDiff := FileToAddedDiff(prop.TargetFile, prop.ProposedContent)

			// Targeted test runner
			var testRunner func() error
			if e.TestRunnerFactory != nil {
				testRunner = e.TestRunnerFactory(sb.TempDir)
			} else if hasGoMod(sb.TempDir) {
				testRunner = defaultGoTestRunner(sb.TempDir)
			}

			// Scope verification rules to sandbox directory so rule source reads the repaired sandbox files
			sandboxRules := scopeRulesToDir(e.Rules, sb.TempDir)

			// Execute VerifyRemediation
			vRes := review.VerifyRemediation(finding, origDiff, repairedDiff, sandboxRules, testRunner)
			finalVerification = vRes
			validationLogs.WriteString(fmt.Sprintf("Attempt %d: status=%s explanation=%s\n", attempt, vRes.Status, vRes.Explanation))

			if vRes.Status == "fixed" {
				verifiedFixed = true
			} else if vRes.Status == "unfixed" && len(vRes.RemainingFindings) > 0 {
				for _, rf := range vRes.RemainingFindings {
					if rf.Rule == finding.Rule && rf.File == finding.File {
						currentFinding = rf
						currentContent = prop.ProposedContent
						break
					}
				}
			}
		}()

		if verifiedFixed {
			break
		}
	}

	result.Proposal = finalProposal
	result.Attempts = attempts
	result.Validation = finalVerification
	result.Error = lastErr

	// 3. Evaluate outcome
	if !verifiedFixed {
		if attempts >= maxAttempts {
			result.Outcome = OutcomeAttemptLimitExceeded
		} else {
			result.Outcome = OutcomeVerificationFailed
		}

		// Durable audit trail entry for failed/discarded proposal
		auditEntry := RepairAuditEntry{
			RepairID:        repairID,
			Timestamp:       time.Now().UTC(),
			OriginalFinding: finding,
			FixerName:       fixer.Name(),
			Patch:           safePatch(finalProposal),
			TargetFile:      finding.File,
			Attempts:        attempts,
			Validation:      finalVerification,
			ValidationLogs:  validationLogs.String(),
			Outcome:         result.Outcome,
			Approved:        false,
			Applied:         false,
			Error:           errString(lastErr),
		}
		_ = AppendRepairAudit(auditPath, auditEntry)
		return result, nil
	}

	// 4. Verification succeeded: handle explicit approval
	if e.DryRun {
		result.Outcome = OutcomeDryRun
		result.Applied = false
		auditEntry := RepairAuditEntry{
			RepairID:        repairID,
			Timestamp:       time.Now().UTC(),
			OriginalFinding: finding,
			FixerName:       fixer.Name(),
			Patch:           finalProposal.Patch,
			TargetFile:      finalProposal.TargetFile,
			Attempts:        attempts,
			Validation:      finalVerification,
			ValidationLogs:  validationLogs.String(),
			Outcome:         OutcomeDryRun,
			Approved:        false,
			Applied:         false,
		}
		_ = AppendRepairAudit(auditPath, auditEntry)
		return result, nil
	}

	approved := false
	if e.ApprovalHandler != nil {
		appr, err := e.ApprovalHandler(finalProposal, finalVerification)
		if err != nil {
			result.Error = err
			result.Outcome = OutcomeRejected
		} else {
			approved = appr
		}
	}

	if !approved {
		// Discard proposal, user's working tree remains untouched
		result.Outcome = OutcomeRejected
		result.Applied = false

		auditEntry := RepairAuditEntry{
			RepairID:        repairID,
			Timestamp:       time.Now().UTC(),
			OriginalFinding: finding,
			FixerName:       fixer.Name(),
			Patch:           finalProposal.Patch,
			TargetFile:      finalProposal.TargetFile,
			Attempts:        attempts,
			Validation:      finalVerification,
			ValidationLogs:  validationLogs.String(),
			Outcome:         OutcomeRejected,
			Approved:        false,
			Applied:         false,
		}
		_ = AppendRepairAudit(auditPath, auditEntry)
		return result, nil
	}

	// 5. Explicitly approved: apply to the real repository working tree
	// GUARANTEE: NEVER auto-commit, NEVER push. Only modify the targeted file.
	if err := ApplyProposalToFile(e.RepoRoot, finalProposal); err != nil {
		result.Outcome = OutcomeVerificationFailed
		result.Applied = false
		result.Error = fmt.Errorf("failed to apply approved proposal to working tree: %w", err)

		auditEntry := RepairAuditEntry{
			RepairID:        repairID,
			Timestamp:       time.Now().UTC(),
			OriginalFinding: finding,
			FixerName:       fixer.Name(),
			Patch:           finalProposal.Patch,
			TargetFile:      finalProposal.TargetFile,
			Attempts:        attempts,
			Validation:      finalVerification,
			ValidationLogs:  validationLogs.String(),
			Outcome:         OutcomeVerificationFailed,
			Approved:        true,
			Applied:         false,
			Error:           errString(result.Error),
		}
		_ = AppendRepairAudit(auditPath, auditEntry)
		return result, result.Error
	}

	result.Outcome = OutcomeApprovedAndApplied
	result.Applied = true

	auditEntry := RepairAuditEntry{
		RepairID:        repairID,
		Timestamp:       time.Now().UTC(),
		OriginalFinding: finding,
		FixerName:       fixer.Name(),
		Patch:           finalProposal.Patch,
		TargetFile:      finalProposal.TargetFile,
		Attempts:        attempts,
		Validation:      finalVerification,
		ValidationLogs:  validationLogs.String(),
		Outcome:         OutcomeApprovedAndApplied,
		Approved:        true,
		Applied:         true,
	}
	_ = AppendRepairAudit(auditPath, auditEntry)
	return result, nil
}

// RepairFindings repairs a collection of findings sequentially.
func (e *RepairEngine) RepairFindings(ctx context.Context, findings []review.Finding) ([]RepairResult, error) {
	results := make([]RepairResult, 0, len(findings))
	for _, f := range findings {
		res, err := e.RepairFinding(ctx, f)
		if err != nil && res == nil {
			return results, err
		}
		if res != nil {
			results = append(results, *res)
		}
	}
	return results, nil
}

func hasGoMod(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "go.mod"))
	return err == nil
}

func defaultGoTestRunner(dir string) func() error {
	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "test", "./...")
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("go test failed: %s: %w", strings.TrimSpace(string(out)), err)
		}
		return nil
	}
}

func safePatch(p *Proposal) string {
	if p == nil {
		return ""
	}
	return p.Patch
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func scopeRulesToDir(rules []review.Rule, dir string) []review.Rule {
	if len(rules) == 0 {
		return rules
	}
	scoped := make([]review.Rule, len(rules))
	for i, r := range rules {
		val := reflect.ValueOf(r)
		if val.Kind() == reflect.Struct {
			valCopy := reflect.New(val.Type()).Elem()
			valCopy.Set(val)
			field := valCopy.FieldByName("RepositoryRoot")
			if field.IsValid() && field.CanSet() && field.Kind() == reflect.String {
				field.SetString(dir)
			}
			fieldWT := valCopy.FieldByName("WorkingTree")
			if fieldWT.IsValid() && fieldWT.CanSet() && fieldWT.Kind() == reflect.Bool {
				fieldWT.SetBool(true)
			}
			if newRule, ok := valCopy.Interface().(review.Rule); ok {
				scoped[i] = newRule
				continue
			}
		} else if val.Kind() == reflect.Pointer && val.Elem().Kind() == reflect.Struct {
			valCopy := reflect.New(val.Elem().Type())
			valCopy.Elem().Set(val.Elem())
			field := valCopy.Elem().FieldByName("RepositoryRoot")
			if field.IsValid() && field.CanSet() && field.Kind() == reflect.String {
				field.SetString(dir)
			}
			fieldWT := valCopy.Elem().FieldByName("WorkingTree")
			if fieldWT.IsValid() && fieldWT.CanSet() && fieldWT.Kind() == reflect.Bool {
				fieldWT.SetBool(true)
			}
			if newRule, ok := valCopy.Interface().(review.Rule); ok {
				scoped[i] = newRule
				continue
			}
		}
		scoped[i] = r
	}
	return scoped
}
