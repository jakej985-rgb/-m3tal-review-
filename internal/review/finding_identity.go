package review

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	parenLineRefRegex  = regexp.MustCompile(`(?i)\((?:(?:at|on|in)\s+)?line\s+\d+(?:,?\s*(?:col|column)\s+\d+)?\)`)
	phraseLineRefRegex = regexp.MustCompile(`(?i)\b(?:at|on|in|,)?\s*line\s+\d+(?:,?\s*(?:col|column)\s+\d+)?\b`)
	colonLineRefRegex  = regexp.MustCompile(`:(?:\d+)(?::\d+)?(?::|\b)`)
	whitespaceRunRegex = regexp.MustCompile(`\s+`)
)

// NormalizeFindingPath cleans and normalizes a file path so path format differences
// (such as ./a/b vs a/b or Windows backslashes) produce identical identities.
func NormalizeFindingPath(path string) string {
	if path == "" {
		return ""
	}
	p := strings.ReplaceAll(path, "\\", "/")
	cleaned := filepath.ToSlash(filepath.Clean(p))
	cleaned = strings.TrimPrefix(cleaned, "./")
	cleaned = strings.TrimPrefix(cleaned, "/")
	return cleaned
}

// SubstantiveFindingSignature extracts the substantive core of a finding,
// decoupling identity from ephemeral line numbers or formatting variations.
func SubstantiveFindingSignature(f Finding) string {
	if strings.TrimSpace(f.Signature) != "" {
		return strings.TrimSpace(f.Signature)
	}
	msg := strings.TrimSpace(f.Message)
	if msg == "" {
		return f.Rule
	}
	// Strip line and column references embedded in messages
	normalized := parenLineRefRegex.ReplaceAllString(msg, "")
	normalized = colonLineRefRegex.ReplaceAllString(normalized, " ")
	normalized = phraseLineRefRegex.ReplaceAllString(normalized, " ")
	normalized = whitespaceRunRegex.ReplaceAllString(strings.TrimSpace(normalized), " ")
	normalized = strings.Trim(normalized, " ,;:")
	if normalized == "" {
		return msg
	}
	return normalized
}

// BaseFindingKey builds the canonical key from rule, normalized path, and substantive signature.
func BaseFindingKey(f Finding) string {
	category := f.Category
	if category == "" {
		category = categoryForRule(f.Rule)
	}
	rule := strings.TrimSpace(f.Rule)
	normPath := NormalizeFindingPath(f.File)
	sig := SubstantiveFindingSignature(f)
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s", category, rule, normPath, sig)
}

// FindingID computes a stable identity for a single finding without relying on line number.
// Line number is preserved as location metadata on f.Line.
func FindingID(f Finding) string {
	if f.ID != "" {
		return f.ID
	}
	key := BaseFindingKey(f)
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:8])
}

// ComputeFindingIDWithOccurrence computes a deterministic finding identity with an occurrence index.
func ComputeFindingIDWithOccurrence(f Finding, occurrence int) string {
	key := BaseFindingKey(f)
	if occurrence > 0 {
		key = fmt.Sprintf("%s\x00%d", key, occurrence)
	}
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:8])
}

// AssignFindingIDs assigns stable identities across a set of findings.
// Findings with identical rule, normalized path, and substantive signature
// are disambiguated deterministically via occurrence ordering, while preserving
// line numbers as location metadata and keeping identities resilient to line shifts.
func AssignFindingIDs(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}
	out := make([]Finding, len(findings))
	copy(out, findings)

	for i := range out {
		if out[i].Category == "" {
			out[i].Category = categoryForRule(out[i].Rule)
		}
	}

	// Group indices by base key
	groups := make(map[string][]int)
	for i, f := range out {
		key := BaseFindingKey(f)
		groups[key] = append(groups[key], i)
	}

	for _, indices := range groups {
		if len(indices) == 1 {
			idx := indices[0]
			if out[idx].ID == "" {
				out[idx].ID = ComputeFindingIDWithOccurrence(out[idx], 0)
			}
			continue
		}

		hasDuplicatesOrEmpty := false
		seenIDs := make(map[string]bool, len(indices))
		for _, idx := range indices {
			if out[idx].ID == "" || seenIDs[out[idx].ID] {
				hasDuplicatesOrEmpty = true
				break
			}
			seenIDs[out[idx].ID] = true
		}

		if hasDuplicatesOrEmpty {
			// Sort duplicate candidates deterministically by line number, then message, etc.
			sort.SliceStable(indices, func(a, b int) bool {
				ia, ib := indices[a], indices[b]
				if out[ia].Line != out[ib].Line {
					return out[ia].Line < out[ib].Line
				}
				if out[ia].Message != out[ib].Message {
					return out[ia].Message < out[ib].Message
				}
				return out[ia].Remediation < out[ib].Remediation
			})

			for occ, idx := range indices {
				out[idx].ID = ComputeFindingIDWithOccurrence(out[idx], occ)
			}
		}
	}

	return out
}
