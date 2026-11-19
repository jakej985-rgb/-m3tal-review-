package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// NormalizeSnippet strips formatting, indentation, and blank lines from a code snippet.
func NormalizeSnippet(s string) string {
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}

// ComputeSignature calculates a stable signature based on rule, file, and normalized content.
func ComputeSignature(rule, file, snippet, msg string) string {
	h := sha256.New()
	normFile := filepath.ToSlash(file)
	normSnippet := NormalizeSnippet(snippet)
	if normSnippet == "" {
		normSnippet = NormalizeSnippet(msg)
	}
	h.Write([]byte(rule + ":" + normFile + ":" + normSnippet))
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// ComputeAnchor creates a semantic anchor based on rule, file, and function/symbol context.
func ComputeAnchor(rule, file string, metadata map[string]string) string {
	normFile := filepath.ToSlash(file)
	fn := ""
	if metadata != nil {
		fn = metadata["function"]
	}
	return rule + ":" + normFile + ":" + fn
}

// TokenSimilarity computes Jaccard similarity across whitespace-delimited word tokens.
func TokenSimilarity(s1, s2 string) float64 {
	tokens1 := strings.Fields(s1)
	tokens2 := strings.Fields(s2)
	if len(tokens1) == 0 && len(tokens2) == 0 {
		return 1.0
	}
	if len(tokens1) == 0 || len(tokens2) == 0 {
		return 0.0
	}

	set1 := make(map[string]bool)
	for _, t := range tokens1 {
		set1[t] = true
	}
	intersect := 0
	union := len(set1)
	for _, t := range tokens2 {
		if set1[t] {
			intersect++
		} else {
			union++
		}
	}
	if union == 0 {
		return 0.0
	}
	return float64(intersect) / float64(union)
}

func matchExactEntry(f review.Finding, sig string, entries []BaselineEntry) *BaselineEntry {
	for i := range entries {
		e := &entries[i]
		if e.ID == f.ID || (e.Signature != "" && e.Signature == sig) {
			return e
		}
	}
	return nil
}

func matchHeuristicEntry(
	f review.Finding,
	anchor string,
	entries []BaselineEntry,
) (*BaselineEntry, bool) {
	normCurrent := NormalizeSnippet(f.Snippet)
	normFile := filepath.ToSlash(f.File)

	for i := range entries {
		e := &entries[i]
		if e.Rule != f.Rule {
			continue
		}
		// Match on same file and anchor
		if e.Anchor != "" && e.Anchor == anchor {
			return e, true
		}
		// Match on same file with high snippet similarity
		if filepath.ToSlash(e.File) == normFile {
			sim := TokenSimilarity(normCurrent, NormalizeSnippet(e.Snippet))
			lineDelta := e.Line - f.Line
			if lineDelta < 0 {
				lineDelta = -lineDelta
			}
			if sim >= 0.7 || (lineDelta <= 25 && sim >= 0.4) {
				return e, true
			}
		}
	}
	return nil, false
}

// FindMatchingBaseline searches entries for a match with f, distinguishing exact from heuristic.
func FindMatchingBaseline(
	f review.Finding,
	entries []BaselineEntry,
) (*BaselineEntry, MatchKind, bool) {
	sig := ComputeSignature(f.Rule, f.File, f.Snippet, f.Message)
	if exact := matchExactEntry(f, sig, entries); exact != nil {
		return exact, MatchExact, true
	}

	anchor := ComputeAnchor(f.Rule, f.File, f.Metadata)
	if heur, ok := matchHeuristicEntry(f, anchor, entries); ok {
		return heur, MatchHeuristic, true
	}

	return nil, "", false
}
