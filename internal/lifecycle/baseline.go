package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// ComputeIntegrityHash generates a deterministic SHA256 hash over baseline entries.
func ComputeIntegrityHash(entries []BaselineEntry) string {
	h := sha256.New()
	for _, e := range entries {
		h.Write([]byte(e.ID + ":" + e.Rule + ":" + e.File + ":" + fmt.Sprint(e.Line) + ":" + e.Severity))
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// NewBaselineManifest constructs a fresh manifest from review findings.
func NewBaselineManifest(findings []review.Finding, commitSHA string) *BaselineManifest {
	var entries []BaselineEntry
	for _, f := range findings {
		ruleID := f.Rule
		if ruleID == "" && len(f.Rules) > 0 {
			ruleID = f.Rules[0]
		}
		sig := ComputeSignature(ruleID, f.File, f.Snippet, f.Message)
		anchor := ComputeAnchor(ruleID, f.File, f.Metadata)
		entries = append(entries, BaselineEntry{
			ID:        f.ID,
			Rule:      ruleID,
			File:      f.File,
			Line:      f.Line,
			Severity:  f.Severity,
			Snippet:   f.Snippet,
			Signature: sig,
			Anchor:    anchor,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ID < entries[j].ID
	})

	hash := ComputeIntegrityHash(entries)

	return &BaselineManifest{
		Version:       "1.0",
		CreatedAt:     time.Now().UTC(),
		CommitSHA:     commitSHA,
		IntegrityHash: hash,
		Findings:      entries,
	}
}

// LoadBaseline safely parses and verifies a baseline manifest file.
func LoadBaseline(path string) (*BaselineManifest, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("baseline %q must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("baseline %q is not a regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline data: %w", err)
	}
	if len(data) > 8<<20 {
		return nil, fmt.Errorf("baseline %q exceeds maximum allowed size (8 MiB)", path)
	}

	var m BaselineManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("corrupt baseline %q: invalid JSON format: %w", path, err)
	}
	if m.Version == "" {
		return nil, fmt.Errorf("incompatible baseline %q: missing required 'version' field", path)
	}

	expectedHash := ComputeIntegrityHash(m.Findings)
	if m.IntegrityHash != expectedHash {
		return nil, fmt.Errorf(
			"corrupt or tampered baseline %q: integrity hash mismatch (expected %s, got %s)",
			path, expectedHash, m.IntegrityHash,
		)
	}

	return &m, nil
}

// SaveBaseline writes a baseline manifest to disk with atomic write safeguards.
func SaveBaseline(path string, manifest *BaselineManifest, allowOverwrite bool) error {
	if manifest == nil {
		return fmt.Errorf("cannot save nil baseline manifest")
	}

	if _, err := os.Stat(path); err == nil && !allowOverwrite {
		return fmt.Errorf("baseline %q already exists; update requires explicit confirmation", path)
	}

	manifest.IntegrityHash = ComputeIntegrityHash(manifest.Findings)
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize baseline: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create baseline directory: %w", err)
	}

	tmpFile := filepath.Join(dir, fmt.Sprintf(".tmp-baseline-%d", time.Now().UnixNano()))
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("write temporary baseline: %w", err)
	}
	if err := os.Rename(tmpFile, path); err != nil {
		if rmErr := os.Remove(tmpFile); rmErr != nil {
			return fmt.Errorf("commit baseline file: %w (cleanup error: %v)", err, rmErr)
		}
		return fmt.Errorf("commit baseline file: %w", err)
	}
	return nil
}
