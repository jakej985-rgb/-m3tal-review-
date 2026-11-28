package languages

import (
	"context"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analyzers"
	"github.com/jakej985-rgb/m3tal-review/internal/planning"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

var (
	reDartEmptyCatch   = regexp.MustCompile(`\bcatch\s*\([^)]*\)\s*\{\s*\}`)
	reDartInsecureHTTP = regexp.MustCompile(`http://[A-Za-z0-9.-]+`)
	reDartPrint        = regexp.MustCompile(`^\s*print\s*\(`)
)

// DartAnalyzer implements static/basic analysis for Dart files.
type DartAnalyzer struct{}

func (DartAnalyzer) Metadata() planning.AnalyzerMetadata {
	return planning.AnalyzerMetadata{
		ID:           "lang-dart",
		Name:         "Dart language analysis",
		Kind:         planning.KindLanguage,
		Languages:    []string{"Dart"},
		Capabilities: []string{"static"},
		Description:  "Dart static and pattern analysis",
	}
}

func (DartAnalyzer) Analyze(_ context.Context, req analyzers.Request) (analyzers.Result, error) {
	var findings []review.Finding
	for _, f := range req.Files {
		lines := strings.Split(f.Content, "\n")
		for idx, raw := range lines {
			line := idx + 1
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" || strings.HasPrefix(trimmed, "//") {
				continue
			}
			if reDartEmptyCatch.MatchString(raw) {
				findings = append(findings, review.Finding{
					Rule: "dart/bug/empty-catch", Category: "bug", Severity: "medium", Confidence: "high",
					File: f.Path, Line: line, Message: "Empty catch block silently swallows Dart exceptions",
					Snippet: trimmed, Remediation: "Log, handle, or rethrow the caught exception.",
				})
			}
			if reDartInsecureHTTP.MatchString(raw) && !strings.Contains(raw, "localhost") && !strings.Contains(raw, "127.0.0.1") {
				findings = append(findings, review.Finding{
					Rule: "dart/security/cleartext-http", Category: "security", Severity: "medium", Confidence: "medium",
					File: f.Path, Line: line, Message: "Cleartext HTTP URL used in Dart source",
					Snippet: trimmed, Remediation: "Use HTTPS for network endpoints.",
				})
			}
			if reDartPrint.MatchString(raw) && !strings.HasSuffix(f.Path, "_test.dart") {
				findings = append(findings, review.Finding{
					Rule: "dart/slop/print-leftover", Category: "slop", Severity: "low", Confidence: "high",
					File: f.Path, Line: line, Message: "print() call left in non-test Dart code",
					Snippet: trimmed, Remediation: "Use a structured logger or debugPrint guarded by kDebugMode.",
				})
			}
		}
	}
	return analyzers.Result{AnalyzerID: "lang-dart", Findings: findings}, nil
}
