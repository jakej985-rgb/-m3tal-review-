// Package history owns the JSONL review-history log: its record type,
// append/read operations, retention pruning, and cross-process locking.
//
// It depends only on the standard library plus fsutil/safetext, so it can be
// used without importing internal/review. Report construction and validation
// deliberately stay in internal/review; see docs/ARCHITECTURE.md.
package history

import "time"

// HistoryEntry is one line of .m3tal-review/history.jsonl.
type HistoryEntry struct {
	Scope        string    `json:"scope,omitempty"`
	RunID        string    `json:"run_id"`
	Timestamp    time.Time `json:"timestamp"`
	Status       string    `json:"status"`
	FindingCount int       `json:"finding_count"`
	Summary      string    `json:"summary"`
}
