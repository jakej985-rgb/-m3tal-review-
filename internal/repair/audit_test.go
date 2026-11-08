package repair

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestAuditLogAppendAndRead(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "repairs.jsonl")

	entry1 := RepairAuditEntry{
		RepairID:  "rep-001",
		Timestamp: time.Now().UTC(),
		OriginalFinding: review.Finding{
			ID:       "f-001",
			Rule:     "world-writable-file-mode",
			File:     "io.go",
			Line:     10,
			Severity: "high",
		},
		FixerName:  "world-writable-file-mode-fixer",
		Patch:      "--- a/io.go\n+++ b/io.go\n",
		TargetFile: "io.go",
		Attempts:   1,
		Validation: review.RemediationVerificationResult{
			FindingID: "f-001",
			Status:    "fixed",
		},
		Outcome:  OutcomeApprovedAndApplied,
		Approved: true,
		Applied:  true,
	}

	entry2 := RepairAuditEntry{
		RepairID:  "rep-002",
		Timestamp: time.Now().UTC(),
		OriginalFinding: review.Finding{
			ID:       "f-002",
			Rule:     "code-slop",
			File:     "eval.go",
			Line:     5,
			Severity: "low",
		},
		FixerName:  "redundant-bool-fixer",
		Patch:      "--- a/eval.go\n+++ b/eval.go\n",
		TargetFile: "eval.go",
		Attempts:   2,
		Validation: review.RemediationVerificationResult{
			FindingID: "f-002",
			Status:    "unfixed",
		},
		Outcome:  OutcomeVerificationFailed,
		Approved: false,
		Applied:  false,
	}

	if err := AppendRepairAudit(auditPath, entry1); err != nil {
		t.Fatalf("append entry 1: %v", err)
	}
	if err := AppendRepairAudit(auditPath, entry2); err != nil {
		t.Fatalf("append entry 2: %v", err)
	}

	entries, err := ReadRepairAudit(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 audit entries, got %d", len(entries))
	}

	if entries[0].RepairID != "rep-001" || entries[0].Outcome != OutcomeApprovedAndApplied || !entries[0].Applied {
		t.Errorf("entry 1 mismatch: %+v", entries[0])
	}
	if entries[1].RepairID != "rep-002" || entries[1].Outcome != OutcomeVerificationFailed || entries[1].Applied {
		t.Errorf("entry 2 mismatch: %+v", entries[1])
	}
}
