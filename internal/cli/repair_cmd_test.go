package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/repair"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestParseRepairOptions(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		expected repairOptions
		wantErr  bool
	}{
		{
			name: "defaults",
			args: []string{},
			expected: repairOptions{
				maxAttempts: 3,
			},
		},
		{
			name: "full options",
			args: []string{"--finding", "f1", "--rule", "code-slop", "--fixer", "trailing-whitespace-fixer", "--max-attempts", "5", "--dry-run", "--yes", "--format", "json", "run-123"},
			expected: repairOptions{
				findingID:   "f1",
				ruleFilter:  "code-slop",
				fixerFilter: "trailing-whitespace-fixer",
				maxAttempts: 5,
				dryRun:      true,
				autoApprove: true,
				formatJSON:  true,
				runID:       "run-123",
			},
		},
		{
			name: "history flag",
			args: []string{"--history"},
			expected: repairOptions{
				maxAttempts: 3,
				showHistory: true,
			},
		},
		{
			name:    "invalid max attempts",
			args:    []string{"--max-attempts", "0"},
			wantErr: true,
		},
		{
			name:    "unknown option",
			args:    []string{"--unknown-flag"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := parseRepairOptions(tc.args)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseRepairOptions() err = %v, wantErr %t", err, tc.wantErr)
			}
			if !tc.wantErr {
				if opts.findingID != tc.expected.findingID ||
					opts.ruleFilter != tc.expected.ruleFilter ||
					opts.fixerFilter != tc.expected.fixerFilter ||
					opts.maxAttempts != tc.expected.maxAttempts ||
					opts.dryRun != tc.expected.dryRun ||
					opts.autoApprove != tc.expected.autoApprove ||
					opts.formatJSON != tc.expected.formatJSON ||
					opts.showHistory != tc.expected.showHistory ||
					opts.runID != tc.expected.runID {
					t.Errorf("opts mismatch:\ngot  %+v\nwant %+v", opts, tc.expected)
				}
			}
		})
	}
}

func TestCommandRepairHistoryEmptyAndPopulated(t *testing.T) {
	repoDir := t.TempDir()
	auditDir := filepath.Join(repoDir, ".m3tal-review")
	if err := os.MkdirAll(auditDir, 0755); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(auditDir, "repairs.jsonl")

	// Empty history
	if err := showRepairHistory(auditPath, false); err != nil {
		t.Fatalf("showRepairHistory empty err: %v", err)
	}

	// Populated history
	entry := repair.RepairAuditEntry{
		RepairID:  "rep-12345",
		Timestamp: time.Now().UTC(),
		OriginalFinding: review.Finding{
			ID:       "find-1",
			Rule:     "world-writable-file-mode",
			File:     "test.go",
			Line:     10,
			Severity: "high",
		},
		FixerName:  "world-writable-file-mode-fixer",
		TargetFile: "test.go",
		Attempts:   1,
		Outcome:    repair.OutcomeApprovedAndApplied,
		Approved:   true,
		Applied:    true,
	}

	if err := repair.AppendRepairAudit(auditPath, entry); err != nil {
		t.Fatal(err)
	}

	if err := showRepairHistory(auditPath, false); err != nil {
		t.Fatalf("showRepairHistory populated err: %v", err)
	}
	if err := showRepairHistory(auditPath, true); err != nil {
		t.Fatalf("showRepairHistory json err: %v", err)
	}
}

func TestCommandRepairNoEligibleFindings(t *testing.T) {
	repoDir := t.TempDir()
	origDir, _ := os.Getwd()
	defer os.Chdir(origDir)
	_ = os.Chdir(repoDir)

	// In non-git directory, should fail git.Available or RepositoryRoot
	err := Run([]string{"repair"})
	if err == nil {
		t.Fatal("expected Run repair in non-git directory to fail")
	}
	if !strings.Contains(err.Error(), "git") && !strings.Contains(err.Error(), "find repository root") {
		t.Errorf("expected git error, got: %v", err)
	}
}

func TestCommandRepairInvalidRunID(t *testing.T) {
	_, err := resolveFindingsForRepair("/tmp", "../../invalid-run-id")
	if err == nil {
		t.Fatal("expected invalid runID to return error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid run ID") {
		t.Errorf("expected 'invalid run ID' error message, got: %v", err)
	}
}
