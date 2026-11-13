package analysis

import (
	"strconv"
	"strings"
)

// Span identifies a source range. Line and Column are 1-based; Offset is
// 0-based. A Span with an empty File is invalid as a primary location but
// may appear on evidence steps that reference non-file entities.
//
// Spans are language-neutral: they deliberately mirror the shape of
// semantic.Position without importing the semantic package, so evidence
// can reference source locations produced by any frontend.
type Span struct {
	File string `json:"file"`

	StartOffset int `json:"start_offset,omitempty"`
	StartLine   int `json:"start_line,omitempty"`
	StartColumn int `json:"start_column,omitempty"`

	EndOffset int `json:"end_offset,omitempty"`
	EndLine   int `json:"end_line,omitempty"`
	EndColumn int `json:"end_column,omitempty"`

	// Snippet optionally carries a short source excerpt for display.
	// It is not part of span identity.
	Snippet string `json:"snippet,omitempty"`
}

// Valid reports whether the span carries usable source information.
func (s Span) Valid() bool { return strings.TrimSpace(s.File) != "" }

// Empty reports whether the span carries no location information at all.
func (s Span) Empty() bool {
	return s.File == "" &&
		s.StartOffset == 0 && s.StartLine == 0 && s.StartColumn == 0 &&
		s.EndOffset == 0 && s.EndLine == 0 && s.EndColumn == 0
}

// SingleLine returns a span covering exactly one line, for callers that
// only know a line number (e.g. adapters over legacy findings).
func SingleLineSpan(file string, line int) Span {
	return Span{File: file, StartLine: line, EndLine: line}
}

// Key returns the canonical serialization of the span used for identity
// hashing. Snippet is excluded so cosmetic edits do not change IDs.
func (s Span) Key() string {
	return strings.Join([]string{
		s.File,
		strconv.Itoa(s.StartOffset),
		strconv.Itoa(s.StartLine),
		strconv.Itoa(s.StartColumn),
		strconv.Itoa(s.EndOffset),
		strconv.Itoa(s.EndLine),
		strconv.Itoa(s.EndColumn),
	}, "\x00")
}
