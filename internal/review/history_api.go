package review

import (
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review/history"
)

type (
	PruneOptions = history.PruneOptions
	PruneItem    = history.PruneItem
	PruneResult  = history.PruneResult
)

// ReadHistory, AppendHistory, PruneHistory, ParseRetentionDuration, and
// ParseRetentionSize delegate to internal/review/history so existing callers
// keep the review package facade.
func ReadHistory(path string) ([]HistoryEntry, error) {
	return history.ReadHistory(path)
}

func AppendHistory(path string, entry HistoryEntry) error {
	return history.AppendHistory(path, entry)
}

func PruneHistory(repositoryRoot string, opts PruneOptions) (PruneResult, error) {
	return history.PruneHistory(repositoryRoot, opts)
}

func ParseRetentionDuration(s string) (time.Duration, error) {
	return history.ParseRetentionDuration(s)
}

func ParseRetentionSize(s string) (int64, error) {
	return history.ParseRetentionSize(s)
}
