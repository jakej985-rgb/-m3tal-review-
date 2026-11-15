package repair

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// Regression (was audit repro): the ApprovalHandler receives a copy of the
// verified Proposal. Mutating it must not change what is applied — the
// verified content is written to the working tree.
func TestAuditApprovalCallbackMutation(t *testing.T) {
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)

	file := "clean.go"
	content := "func main() {   \n}\n"
	if err := os.WriteFile(filepath.Join(repoDir, file), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	finding := review.Finding{
		ID:       "audit-cb-mut",
		Rule:     "code-slop",
		Severity: "low",
		File:     file,
		Message:  "Trailing whitespace detected",
	}

	engine := NewRepairEngine(repoDir, nil)
	engine.ApprovalHandler = func(prop *Proposal, v review.RemediationVerificationResult) (bool, error) {
		// Attempt to mutate the proposal post-verification; the handler
		// receives a copy, so this must have no effect on the outcome.
		prop.ProposedContent = "package pwned\nfunc main() { os.RemoveAll(\"/\") }\n"
		return true, nil
	}

	res, err := engine.RepairFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected engine error: %v", err)
	}
	if res.Outcome != OutcomeApprovedAndApplied || !res.Applied {
		t.Fatalf("expected approved_and_applied, got outcome=%s applied=%t err=%v", res.Outcome, res.Applied, res.Error)
	}

	disk, err := os.ReadFile(filepath.Join(repoDir, file))
	if err != nil {
		t.Fatal(err)
	}

	verified := res.Proposal.ProposedContent
	if string(disk) != verified {
		t.Fatalf("disk content diverged from verified proposal:\ndisk=%q\nverified=%q", string(disk), verified)
	}
	if string(disk) == "package pwned\nfunc main() { os.RemoveAll(\"/\") }\n" {
		t.Fatal("unverified mutated content was applied to working tree")
	}
	// The verified fix is the trailing-whitespace-stripped content.
	if string(disk) != "func main() {\n}\n" {
		t.Fatalf("expected verified fix content, got %q", string(disk))
	}
}

// Regression (was audit repro): when the audit log cannot be persisted, the
// repair still applies but the result carries AuditError and returns an
// error so the durability failure is never silent.
func TestAuditApprovalAuditPersistFailure(t *testing.T) {
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)

	file := "clean.go"
	content := "func main() {   \n}\n"
	if err := os.WriteFile(filepath.Join(repoDir, file), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	finding := review.Finding{
		ID:       "audit-persist",
		Rule:     "code-slop",
		Severity: "low",
		File:     file,
		Message:  "Trailing whitespace detected",
	}

	engine := NewRepairEngine(repoDir, nil)
	engine.ApprovalHandler = func(prop *Proposal, v review.RemediationVerificationResult) (bool, error) {
		return true, nil
	}
	// Point the audit path at a directory: every append must fail.
	engine.AuditPath = repoDir

	res, err := engine.RepairFinding(context.Background(), finding)
	if res == nil {
		t.Fatal("expected result")
	}
	if res.Outcome != OutcomeApprovedAndApplied || !res.Applied {
		t.Fatalf("repair should still apply, got outcome=%s applied=%t", res.Outcome, res.Applied)
	}
	if res.AuditError == "" {
		t.Fatal("expected AuditError to be set when audit persistence fails")
	}
	if err == nil {
		t.Fatal("expected durability error to be returned")
	}

	disk, _ := os.ReadFile(filepath.Join(repoDir, file))
	if string(disk) != "func main() {\n}\n" {
		t.Fatalf("expected verified fix applied, got %q", string(disk))
	}
}
