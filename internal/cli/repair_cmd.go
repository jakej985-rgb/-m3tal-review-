package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
	"github.com/jakej985-rgb/m3tal-review/internal/repair"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

type repairOptions struct {
	findingID   string
	ruleFilter  string
	fixerFilter string
	maxAttempts int
	dryRun      bool
	autoApprove bool
	showHistory bool
	formatJSON  bool
	runID       string
}

func parseRepairOptions(args []string) (repairOptions, error) {
	opts := repairOptions{
		maxAttempts: 3,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--finding":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--finding requires a finding ID")
			}
			i++
			opts.findingID = args[i]
		case "--rule":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--rule requires a rule name")
			}
			i++
			opts.ruleFilter = args[i]
		case "--fixer":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--fixer requires a fixer name")
			}
			i++
			opts.fixerFilter = args[i]
		case "--max-attempts":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--max-attempts requires a number")
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 1 {
				return opts, fmt.Errorf("invalid --max-attempts %q", args[i])
			}
			opts.maxAttempts = n
		case "--dry-run":
			opts.dryRun = true
		case "--yes", "--approve":
			opts.autoApprove = true
		case "--format":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--format requires a value")
			}
			i++
			if args[i] != "json" {
				return opts, fmt.Errorf("invalid --format %q; expected json", args[i])
			}
			opts.formatJSON = true
		case "--history", "history":
			opts.showHistory = true
		default:
			if strings.HasPrefix(arg, "-") {
				return opts, fmt.Errorf("unknown repair option %q", arg)
			}
			if opts.runID == "" {
				opts.runID = arg
			} else {
				return opts, fmt.Errorf("unexpected argument %q", arg)
			}
		}
	}

	return opts, nil
}

func commandRepair(args []string) error {
	opts, err := parseRepairOptions(args)
	if err != nil {
		return err
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	if err := git.Available(); err != nil {
		return err
	}

	repositoryRoot, err := git.RepositoryRoot(workingDir)
	if err != nil {
		return err
	}

	auditPath := filepath.Join(repositoryRoot, ".m3tal-review", "repairs.jsonl")
	if err := ensureReviewStorageSafe(repositoryRoot, auditPath); err != nil {
		return err
	}

	// If history requested, display repair audit trail
	if opts.showHistory {
		return showRepairHistory(auditPath, opts.formatJSON)
	}

	// Resolve findings to repair
	findings, err := resolveFindingsForRepair(repositoryRoot, opts.runID)
	if err != nil {
		return err
	}

	if len(findings) == 0 {
		fmt.Println("No findings found eligible for repair.")
		return nil
	}

	// Filter findings
	var eligible []review.Finding
	for _, f := range findings {
		if opts.findingID != "" && f.ID != opts.findingID {
			continue
		}
		if opts.ruleFilter != "" && f.Rule != opts.ruleFilter {
			continue
		}
		fixer := repair.FindFixerForFinding(f)
		if fixer == nil {
			continue
		}
		if opts.fixerFilter != "" && fixer.Name() != opts.fixerFilter {
			continue
		}
		eligible = append(eligible, f)
	}

	if len(eligible) == 0 {
		fmt.Println("No findings matched repair criteria or allowlisted fixers.")
		return nil
	}

	rules := defaultRules(repositoryRoot)
	engine := repair.NewRepairEngine(repositoryRoot, rules)
	engine.MaxAttempts = opts.maxAttempts
	engine.DryRun = opts.dryRun
	engine.AuditPath = auditPath

	// Configure approval handler
	engine.ApprovalHandler = func(prop *repair.Proposal, v review.RemediationVerificationResult) (bool, error) {
		if opts.autoApprove {
			return true, nil
		}
		return promptInteractiveApproval(prop, v)
	}

	ctx := context.Background()
	results, err := engine.RepairFindings(ctx, eligible)
	if err != nil {
		return fmt.Errorf("repair execution error: %w", err)
	}

	if opts.formatJSON {
		out, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}

	printRepairSummary(results)
	return nil
}

func resolveFindingsForRepair(repositoryRoot, runID string) ([]review.Finding, error) {
	if runID != "" {
		if !review.IsValidRunID(runID) {
			return nil, fmt.Errorf("invalid run ID %q: expected 16 lowercase hexadecimal characters", runID)
		}
		reportPath := filepath.Join(repositoryRoot, ".m3tal-review", "reports", runID+".json")
		if err := ensureReviewStorageSafe(repositoryRoot, reportPath); err != nil {
			return nil, err
		}
		report, err := review.ReadReport(reportPath)
		if err != nil {
			return nil, fmt.Errorf("read report %q: %w", runID, err)
		}
		return report.Findings, nil
	}

	// Check latest history report
	historyPath := filepath.Join(repositoryRoot, ".m3tal-review", "history.jsonl")
	if entries, err := review.ReadHistory(historyPath); err == nil && len(entries) > 0 {
		latest := entries[len(entries)-1]
		if review.IsValidRunID(latest.RunID) {
			reportPath := filepath.Join(repositoryRoot, ".m3tal-review", "reports", latest.RunID+".json")
			if err := ensureReviewStorageSafe(repositoryRoot, reportPath); err == nil {
				if report, err := review.ReadReport(reportPath); err == nil && len(report.Findings) > 0 {
					return report.Findings, nil
				}
			}
		}
	}

	// Fallback to checking staged diff
	diff, err := git.StagedDiff(repositoryRoot)
	if err == nil && strings.TrimSpace(diff) != "" {
		findings := review.NewEngine(defaultRules(repositoryRoot)...).Run(diff)
		findings = review.ApplyFindingFilters(diff, findings, repositoryRoot, false)
		return findings, nil
	}

	// Fallback to checking unstaged working tree diff
	wtDiff, err := git.UnstagedDiff(repositoryRoot)
	if err == nil && strings.TrimSpace(wtDiff) != "" {
		findings := review.NewEngine(defaultRules(repositoryRoot)...).Run(wtDiff)
		findings = review.ApplyFindingFilters(wtDiff, findings, repositoryRoot, true)
		return findings, nil
	}

	return nil, nil
}

func promptInteractiveApproval(prop *repair.Proposal, v review.RemediationVerificationResult) (bool, error) {
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("Proposed Remediation for [%s] %s:%d\n", prop.Finding.Severity, prop.TargetFile, prop.Finding.Line)
	fmt.Printf("Rule: %s | Fixer: %s\n", prop.Finding.Rule, prop.FixerName)
	fmt.Printf("Verification: %s (%s)\n", v.Status, v.Explanation)
	fmt.Println("Patch:")
	fmt.Println(prop.Patch)
	fmt.Print("Apply this patch to working tree? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false, nil
	}
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes", nil
}

func printRepairSummary(results []repair.RepairResult) {
	fmt.Println("================================================================================")
	fmt.Printf("M3TAL Repair Summary: %d finding(s) evaluated\n", len(results))
	fmt.Println("================================================================================")

	appliedCount := 0
	for _, res := range results {
		statusStr := string(res.Outcome)
		switch res.Outcome {
		case repair.OutcomeApprovedAndApplied:
			appliedCount++
			fmt.Printf("[APPLIED] %s (%s): %s\n", res.Finding.File, res.Finding.Rule, res.Proposal.Explanation)
		case repair.OutcomeRejected:
			fmt.Printf("[REJECTED] %s (%s): Proposal discarded, working tree untouched\n", res.Finding.File, res.Finding.Rule)
		case repair.OutcomeDryRun:
			fmt.Printf("[DRY-RUN] %s (%s): Verified fixed in sandbox, working tree untouched\n", res.Finding.File, res.Finding.Rule)
		case repair.OutcomeVerificationFailed:
			fmt.Printf("[FAILED] %s (%s): Verification failed (%s)\n", res.Finding.File, res.Finding.Rule, res.Validation.Explanation)
		case repair.OutcomeAttemptLimitExceeded:
			fmt.Printf("[ATTEMPTS-EXCEEDED] %s (%s): Exceeded %d repair attempt(s)\n", res.Finding.File, res.Finding.Rule, res.Attempts)
		default:
			fmt.Printf("[%s] %s (%s)\n", statusStr, res.Finding.File, res.Finding.Rule)
		}
	}

	if appliedCount > 0 {
		fmt.Println("\nNote: Patches were applied to the working tree without committing.")
		fmt.Println("Review changes and commit or discard manually when ready.")
	}
}

func showRepairHistory(auditPath string, formatJSON bool) error {
	entries, err := repair.ReadRepairAudit(auditPath)
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		fmt.Println("No repair history found.")
		return nil
	}

	if formatJSON {
		out, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}

	fmt.Println("M3TAL Review Repair History")
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		fmt.Printf("[%s] %s | %s | %s:%d | %s | attempts: %d\n",
			e.Outcome,
			e.Timestamp.Format("2006-01-02 15:04:05 UTC"),
			e.RepairID,
			e.TargetFile,
			e.OriginalFinding.Line,
			e.FixerName,
			e.Attempts,
		)
	}
	return nil
}
