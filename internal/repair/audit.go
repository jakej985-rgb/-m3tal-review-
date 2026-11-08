package repair

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// RepairOutcome enumerates terminal outcomes for a repair attempt.
type RepairOutcome string

const (
	OutcomeApprovedAndApplied   RepairOutcome = "approved_and_applied"
	OutcomeRejected             RepairOutcome = "rejected"
	OutcomeVerificationFailed   RepairOutcome = "verification_failed"
	OutcomeAttemptLimitExceeded RepairOutcome = "attempt_limit_exceeded"
	OutcomeDryRun               RepairOutcome = "dry_run"
	OutcomeDiscarded            RepairOutcome = "discarded"
	OutcomeNoFixer              RepairOutcome = "no_eligible_fixer"
)

// RepairAuditEntry records the full lifecycle, patch, validation logs, and durable outcome of a repair.
type RepairAuditEntry struct {
	RepairID        string                               `json:"repair_id"`
	Timestamp       time.Time                            `json:"timestamp"`
	OriginalFinding review.Finding                       `json:"original_finding"`
	FixerName       string                               `json:"fixer_name"`
	Patch           string                               `json:"patch"`
	TargetFile      string                               `json:"target_file"`
	Attempts        int                                  `json:"attempts"`
	Validation      review.RemediationVerificationResult `json:"validation"`
	ValidationLogs  string                               `json:"validation_logs,omitempty"`
	Outcome         RepairOutcome                        `json:"outcome"`
	Approved        bool                                 `json:"approved"`
	Applied         bool                                 `json:"applied"`
	Error           string                               `json:"error,omitempty"`
}

var auditMu sync.Mutex

// AppendRepairAudit writes a durable JSONL audit entry to path, syncing data to disk.
func AppendRepairAudit(path string, entry RepairAuditEntry) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("audit path cannot be empty")
	}

	auditMu.Lock()
	defer auditMu.Unlock()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create audit directory: %w", err)
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}
	data = append(data, '\n')

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync audit log: %w", err)
	}

	return nil
}

// ReadRepairAudit reads all repair audit entries from path.
func ReadRepairAudit(path string) ([]RepairAuditEntry, error) {
	auditMu.Lock()
	defer auditMu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []RepairAuditEntry{}, nil
		}
		return nil, fmt.Errorf("read audit log %q: %w", path, err)
	}

	var entries []RepairAuditEntry
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry RepairAuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("parse audit log line %d: %w", lineNum+1, err)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}
