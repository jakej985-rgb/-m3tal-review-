package review

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSuppressionAudit_Lifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	// 1. Add suppression
	expires := time.Now().UTC().Add(30 * 24 * time.Hour)
	evAdd, err := AppendSuppressionEvent(auditPath, SuppressionEvent{
		Action:        ActionAdd,
		SuppressionID: "supp-1",
		Rule:          "hardcoded-credential",
		File:          "config/keys.go",
		Line:          42,
		Reason:        "Test fixture key",
		Actor:         "alice",
		ExpiresAt:     &expires,
	})
	if err != nil {
		t.Fatalf("AppendSuppressionEvent(add) failed: %v", err)
	}
	if evAdd.EventID == "" || evAdd.Checksum == "" || evAdd.PrevHash != "" {
		t.Errorf("unexpected first event state: %+v", evAdd)
	}

	// 2. Edit suppression
	evEdit, err := AppendSuppressionEvent(auditPath, SuppressionEvent{
		Action:        ActionEdit,
		SuppressionID: "supp-1",
		Rule:          "hardcoded-credential",
		File:          "config/keys.go",
		Line:          45,
		Reason:        "Moved fixture key down three lines",
		Actor:         "bob",
	})
	if err != nil {
		t.Fatalf("AppendSuppressionEvent(edit) failed: %v", err)
	}
	if evEdit.PrevHash != evAdd.Checksum {
		t.Errorf("expected PrevHash %q, got %q", evAdd.Checksum, evEdit.PrevHash)
	}

	// 3. Expire suppression
	evExpire, err := AppendSuppressionEvent(auditPath, SuppressionEvent{
		Action:        ActionExpire,
		SuppressionID: "supp-1",
		Rule:          "hardcoded-credential",
		File:          "config/keys.go",
		Reason:        "Retention expired",
		Actor:         "system",
	})
	if err != nil {
		t.Fatalf("AppendSuppressionEvent(expire) failed: %v", err)
	}
	if evExpire.PrevHash != evEdit.Checksum {
		t.Errorf("expected PrevHash %q, got %q", evEdit.Checksum, evExpire.PrevHash)
	}

	// 4. Remove suppression
	evRemove, err := AppendSuppressionEvent(auditPath, SuppressionEvent{
		Action:        ActionRemove,
		SuppressionID: "supp-1",
		Rule:          "hardcoded-credential",
		File:          "config/keys.go",
		Reason:        "Underlying key rotated to env var",
		Actor:         "charlie",
	})
	if err != nil {
		t.Fatalf("AppendSuppressionEvent(remove) failed: %v", err)
	}
	if evRemove.PrevHash != evExpire.Checksum {
		t.Errorf("expected PrevHash %q, got %q", evExpire.Checksum, evRemove.PrevHash)
	}

	// Read and verify full trail
	events, err := ReadSuppressionAudit(auditPath)
	if err != nil {
		t.Fatalf("ReadSuppressionAudit failed: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}

	tamperErrors := VerifySuppressionAuditTrail(events)
	if len(tamperErrors) > 0 {
		t.Fatalf("expected zero tamper errors, got: %+v", tamperErrors)
	}
}

func TestSuppressionAudit_TamperSafety(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	for i := 0; i < 3; i++ {
		_, err := AppendSuppressionEvent(auditPath, SuppressionEvent{
			Action:        ActionAdd,
			SuppressionID: fmt.Sprintf("supp-%d", i),
			Rule:          "rule",
			File:          "main.go",
			Reason:        fmt.Sprintf("reason %d", i),
			Actor:         "dev",
		})
		if err != nil {
			t.Fatalf("append %d failed: %v", i, err)
		}
	}

	events, err := ReadSuppressionAudit(auditPath)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	// 1. Untampered events must have 0 errors
	if errs := VerifySuppressionAuditTrail(events); len(errs) != 0 {
		t.Fatalf("expected 0 tamper errors on valid trail, got %d", len(errs))
	}

	// 2. Tamper with Reason on event 1
	tampered := make([]SuppressionEvent, len(events))
	copy(tampered, events)
	tampered[1].Reason = "malicious alteration"
	errs := VerifySuppressionAuditTrail(tampered)
	if len(errs) == 0 {
		t.Errorf("expected tamper error when Reason was modified")
	}

	// 3. Tamper by deleting middle event
	tamperedDeleted := []SuppressionEvent{events[0], events[2]}
	errs = VerifySuppressionAuditTrail(tamperedDeleted)
	if len(errs) == 0 {
		t.Errorf("expected broken hash chain error when event was deleted")
	}

	// 4. Tamper by reordering events
	tamperedReordered := []SuppressionEvent{events[1], events[0], events[2]}
	errs = VerifySuppressionAuditTrail(tamperedReordered)
	if len(errs) == 0 {
		t.Errorf("expected broken hash chain error when events were reordered")
	}

	// 5. Tamper with Checksum directly
	tamperedChecksum := make([]SuppressionEvent, len(events))
	copy(tamperedChecksum, events)
	tamperedChecksum[0].Checksum = "0000000000000000000000000000000000000000000000000000000000000000"
	errs = VerifySuppressionAuditTrail(tamperedChecksum)
	if len(errs) == 0 {
		t.Errorf("expected tamper error when checksum was altered")
	}
}

func TestSuppressionAudit_ConcurrentLogging(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "concurrent_audit.jsonl")

	const workerCount = 20
	const eventsPerWorker = 5
	const totalExpected = workerCount * eventsPerWorker

	var wg sync.WaitGroup
	errCh := make(chan error, totalExpected)

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for e := 0; e < eventsPerWorker; e++ {
				_, err := AppendSuppressionEvent(auditPath, SuppressionEvent{
					Action:        ActionAdd,
					SuppressionID: fmt.Sprintf("supp-%d-%d", workerID, e),
					Rule:          "test-rule",
					File:          "file.go",
					Reason:        fmt.Sprintf("worker %d event %d", workerID, e),
					Actor:         fmt.Sprintf("worker-%d", workerID),
				})
				if err != nil {
					errCh <- err
				}
			}
		}(w)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent append error: %v", err)
	}

	events, err := ReadSuppressionAudit(auditPath)
	if err != nil {
		t.Fatalf("ReadSuppressionAudit failed: %v", err)
	}
	if len(events) != totalExpected {
		t.Fatalf("expected %d events, got %d", totalExpected, len(events))
	}

	tamperErrors := VerifySuppressionAuditTrail(events)
	if len(tamperErrors) > 0 {
		t.Fatalf("concurrent logging resulted in tamper errors: %+v", tamperErrors)
	}
}

func TestSuppressionAudit_Retention(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	for i := 0; i < 10; i++ {
		_, err := AppendSuppressionEvent(auditPath, SuppressionEvent{
			Action:        ActionAdd,
			SuppressionID: fmt.Sprintf("supp-%d", i),
			Rule:          "rule",
			File:          "main.go",
			Reason:        fmt.Sprintf("entry %d", i),
			Actor:         "dev",
		})
		if err != nil {
			t.Fatalf("append %d failed: %v", i, err)
		}
	}

	// Prune to keep 4 events
	pruned, err := PruneSuppressionAudit(auditPath, 4)
	if err != nil {
		t.Fatalf("PruneSuppressionAudit failed: %v", err)
	}
	if pruned != 6 {
		t.Errorf("expected 6 pruned events, got %d", pruned)
	}

	events, err := ReadSuppressionAudit(auditPath)
	if err != nil {
		t.Fatalf("read after prune failed: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("expected 4 retained events, got %d", len(events))
	}

	// First retained event should be supp-6
	if events[0].SuppressionID != "supp-6" {
		t.Errorf("expected first retained event to be supp-6, got %s", events[0].SuppressionID)
	}
	// Last retained event should be supp-9
	if events[3].SuppressionID != "supp-9" {
		t.Errorf("expected last retained event to be supp-9, got %s", events[3].SuppressionID)
	}
}
