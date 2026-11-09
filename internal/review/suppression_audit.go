package review

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type SuppressionAction string

const (
	ActionAdd    SuppressionAction = "add"
	ActionEdit   SuppressionAction = "edit"
	ActionExpire SuppressionAction = "expire"
	ActionRemove SuppressionAction = "remove"
)

var ValidSuppressionActions = map[SuppressionAction]bool{
	ActionAdd:    true,
	ActionEdit:   true,
	ActionExpire: true,
	ActionRemove: true,
}

type SuppressionEvent struct {
	EventID       string            `json:"event_id"`
	Timestamp     time.Time         `json:"timestamp"`
	Action        SuppressionAction `json:"action"`
	SuppressionID string            `json:"suppression_id"`
	Rule          string            `json:"rule"`
	File          string            `json:"file"`
	Line          int               `json:"line,omitempty"`
	Reason        string            `json:"reason"`
	Actor         string            `json:"actor"`
	ExpiresAt     *time.Time        `json:"expires_at,omitempty"`
	PrevHash      string            `json:"prev_hash,omitempty"`
	Checksum      string            `json:"checksum"`
}

type TamperError struct {
	Line     int    `json:"line"`
	EventID  string `json:"event_id,omitempty"`
	Field    string `json:"field"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Message  string `json:"message"`
}

func (e TamperError) Error() string {
	return fmt.Sprintf("audit tamper detected at line %d (event %s): %s", e.Line, e.EventID, e.Message)
}

var suppressionAuditMu sync.Mutex

func ComputeSuppressionChecksum(e SuppressionEvent) string {
	expiresStr := ""
	if e.ExpiresAt != nil && !e.ExpiresAt.IsZero() {
		expiresStr = e.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}

	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		e.EventID,
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		string(e.Action),
		e.SuppressionID,
		e.Rule,
		e.File,
		strconv.Itoa(e.Line),
		e.Reason,
		e.Actor,
		expiresStr,
		e.PrevHash,
	)

	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

func generateEventID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func currentActor() string {
	for _, env := range []string{"M3TAL_ACTOR", "USER", "USERNAME", "LOGNAME"} {
		if val := os.Getenv(env); val != "" {
			return val
		}
	}
	return "system"
}

// AppendSuppressionEvent writes an auditable suppression event to auditPath.
// It maintains cryptographic tamper-evident chaining, file locking, and durability sync.
func AppendSuppressionEvent(auditPath string, event SuppressionEvent) (SuppressionEvent, error) {
	if strings.TrimSpace(auditPath) == "" {
		return event, fmt.Errorf("audit path cannot be empty")
	}

	if !ValidSuppressionActions[event.Action] {
		return event, fmt.Errorf("invalid suppression action %q; valid: add, edit, expire, remove", event.Action)
	}

	suppressionAuditMu.Lock()
	defer suppressionAuditMu.Unlock()

	dir := filepath.Dir(auditPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return event, fmt.Errorf("create suppression audit directory: %w", err)
	}

	lockPath := auditPath + ".lock"
	unlock, err := lockHistory(lockPath)
	if err != nil {
		return event, fmt.Errorf("lock suppression audit: %w", err)
	}
	defer unlock()

	// Fill defaults
	if event.EventID == "" {
		event.EventID = generateEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	} else {
		event.Timestamp = event.Timestamp.UTC()
	}
	if event.Actor == "" {
		event.Actor = currentActor()
	}
	if event.SuppressionID == "" {
		// Deterministic suppression ID if not provided
		h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", event.Rule, event.File, event.Line)))
		event.SuppressionID = hex.EncodeToString(h[:8])
	}

	// Read last entry to obtain previous checksum
	lastChecksum := ""
	if data, err := os.ReadFile(auditPath); err == nil && len(data) > 0 {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			var lastEvent SuppressionEvent
			if err := json.Unmarshal([]byte(lines[len(lines)-1]), &lastEvent); err == nil {
				lastChecksum = lastEvent.Checksum
			}
		}
	}

	event.PrevHash = lastChecksum
	event.Checksum = ComputeSuppressionChecksum(event)

	data, err := json.Marshal(event)
	if err != nil {
		return event, fmt.Errorf("marshal suppression event: %w", err)
	}
	data = append(data, '\n')

	f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return event, fmt.Errorf("open suppression audit log: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return event, fmt.Errorf("write suppression audit log: %w", err)
	}

	if err := f.Sync(); err != nil {
		return event, fmt.Errorf("sync suppression audit log: %w", err)
	}

	return event, nil
}

// ReadSuppressionAudit reads all suppression audit entries from auditPath.
func ReadSuppressionAudit(auditPath string) ([]SuppressionEvent, error) {
	suppressionAuditMu.Lock()
	defer suppressionAuditMu.Unlock()

	data, err := os.ReadFile(auditPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []SuppressionEvent{}, nil
		}
		return nil, fmt.Errorf("read suppression audit log %q: %w", auditPath, err)
	}

	var events []SuppressionEvent
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev SuppressionEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return nil, fmt.Errorf("parse suppression audit line %d: %w", lineNum+1, err)
		}
		events = append(events, ev)
	}

	return events, nil
}

// VerifySuppressionAuditTrail verifies the tamper-safety and cryptographic hash chain of suppression events.
func VerifySuppressionAuditTrail(events []SuppressionEvent) []TamperError {
	var errors []TamperError

	var expectedPrevHash string
	for i, ev := range events {
		lineNum := i + 1

		if ev.EventID == "" {
			errors = append(errors, TamperError{
				Line:    lineNum,
				Field:   "event_id",
				Message: "missing event_id",
			})
		}

		if ev.Timestamp.IsZero() {
			errors = append(errors, TamperError{
				Line:    lineNum,
				EventID: ev.EventID,
				Field:   "timestamp",
				Message: "missing or zero timestamp",
			})
		}

		// Verify previous hash chain
		if ev.PrevHash != expectedPrevHash {
			errors = append(errors, TamperError{
				Line:     lineNum,
				EventID:  ev.EventID,
				Field:    "prev_hash",
				Expected: expectedPrevHash,
				Actual:   ev.PrevHash,
				Message:  fmt.Sprintf("broken hash chain: expected prev_hash %q, got %q", expectedPrevHash, ev.PrevHash),
			})
		}

		// Verify checksum
		expectedChecksum := ComputeSuppressionChecksum(ev)
		if ev.Checksum != expectedChecksum {
			errors = append(errors, TamperError{
				Line:     lineNum,
				EventID:  ev.EventID,
				Field:    "checksum",
				Expected: expectedChecksum,
				Actual:   ev.Checksum,
				Message:  fmt.Sprintf("checksum mismatch: expected %q, got %q (data tampered)", expectedChecksum, ev.Checksum),
			})
		}

		expectedPrevHash = ev.Checksum
	}

	return errors
}

// PruneSuppressionAudit prunes old audit events while preserving hash chain continuity.
func PruneSuppressionAudit(auditPath string, retainCount int) (int, error) {
	if retainCount < 0 {
		return 0, fmt.Errorf("retainCount must be non-negative: %d", retainCount)
	}

	suppressionAuditMu.Lock()
	defer suppressionAuditMu.Unlock()

	lockPath := auditPath + ".lock"
	unlock, err := lockHistory(lockPath)
	if err != nil {
		return 0, fmt.Errorf("lock suppression audit for pruning: %w", err)
	}
	defer unlock()

	data, err := os.ReadFile(auditPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read suppression audit: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var events []SuppressionEvent
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		var ev SuppressionEvent
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			return 0, fmt.Errorf("decode suppression event: %w", err)
		}
		events = append(events, ev)
	}

	if len(events) <= retainCount {
		return 0, nil
	}

	prunedCount := len(events) - retainCount
	retained := events[prunedCount:]

	// Atomic rewrite
	dir := filepath.Dir(auditPath)
	tempFile, err := os.CreateTemp(dir, "suppression-prune-*.tmp")
	if err != nil {
		return 0, fmt.Errorf("create temp audit file: %w", err)
	}
	tempPath := tempFile.Name()

	cleanup := true
	defer func() {
		if cleanup {
			_ = tempFile.Close()
			_ = os.Remove(tempPath)
		}
	}()

	_ = tempFile.Chmod(0644)

	for _, ev := range retained {
		d, err := json.Marshal(ev)
		if err != nil {
			return 0, fmt.Errorf("marshal event: %w", err)
		}
		if _, err := tempFile.Write(append(d, '\n')); err != nil {
			return 0, fmt.Errorf("write temp event: %w", err)
		}
	}

	if err := tempFile.Sync(); err != nil {
		return 0, fmt.Errorf("sync temp audit file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return 0, fmt.Errorf("close temp audit file: %w", err)
	}

	if err := os.Rename(tempPath, auditPath); err != nil {
		return 0, fmt.Errorf("atomically replace audit file: %w", err)
	}

	cleanup = false
	return prunedCount, nil
}
