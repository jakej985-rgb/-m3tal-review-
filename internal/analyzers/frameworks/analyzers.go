package frameworks

import (
	"context"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analyzers"
	"github.com/jakej985-rgb/m3tal-review/internal/planning"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

var (
	reAsyncSetState  = regexp.MustCompile(`\bsetState\s*\(`)
	reReactDanger    = regexp.MustCompile(`dangerouslySetInnerHTML\s*=`)
	reUseEffectAsync = regexp.MustCompile(`useEffect\s*\(\s*async\b`)
)

// FlutterAnalyzer checks Flutter-specific widget lifecycle issues.
type FlutterAnalyzer struct{}

func (FlutterAnalyzer) Metadata() planning.AnalyzerMetadata {
	return planning.AnalyzerMetadata{
		ID: "fw-flutter", Name: "Flutter analysis", Kind: planning.KindFramework,
		Frameworks: []string{"Flutter"}, Languages: []string{"Dart"},
		Capabilities: []string{"framework"},
		Description:  "Flutter widget, accessibility, and lifecycle rules",
	}
}

func (FlutterAnalyzer) Analyze(_ context.Context, req analyzers.Request) (analyzers.Result, error) {
	var findings []review.Finding
	for _, f := range req.Files {
		if !strings.HasSuffix(f.Path, ".dart") {
			continue
		}
		hasAwait := strings.Contains(f.Content, "await ")
		hasMounted := strings.Contains(f.Content, "mounted")
		if hasAwait && !hasMounted {
			for idx, raw := range strings.Split(f.Content, "\n") {
				if reAsyncSetState.MatchString(raw) {
					findings = append(findings, review.Finding{
						Rule: "flutter/bug/setstate-after-await", Category: "bug", Severity: "medium", Confidence: "medium",
						File: f.Path, Line: idx + 1, Message: "setState() called in async file without mounted check",
						Snippet: strings.TrimSpace(raw), Remediation: "Check 'if (!mounted) return;' before calling setState() after await.",
					})
				}
			}
		}
	}
	return analyzers.Result{AnalyzerID: "fw-flutter", Findings: findings}, nil
}

// ReactAnalyzer checks React-specific hooks and XSS sinks.
type ReactAnalyzer struct{}

func (ReactAnalyzer) Metadata() planning.AnalyzerMetadata {
	return planning.AnalyzerMetadata{
		ID: "fw-react", Name: "React analysis", Kind: planning.KindFramework,
		Frameworks: []string{"React"}, Languages: []string{"JavaScript", "TypeScript"},
		Capabilities: []string{"framework"},
		Description:  "React hook and XSS sink rules",
	}
}

func (ReactAnalyzer) Analyze(_ context.Context, req analyzers.Request) (analyzers.Result, error) {
	var findings []review.Finding
	for _, f := range req.Files {
		for idx, raw := range strings.Split(f.Content, "\n") {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" || strings.HasPrefix(trimmed, "//") {
				continue
			}
			if reReactDanger.MatchString(raw) {
				findings = append(findings, review.Finding{
					Rule: "react/security/dangerously-set-inner-html", Category: "security", Severity: "high", Confidence: "high",
					File: f.Path, Line: idx + 1, Message: "dangerouslySetInnerHTML risks DOM XSS",
					Snippet: trimmed, Remediation: "Render escaped JSX or sanitize HTML with DOMPurify.",
				})
			}
			if reUseEffectAsync.MatchString(raw) {
				findings = append(findings, review.Finding{
					Rule: "react/bug/async-use-effect", Category: "bug", Severity: "medium", Confidence: "high",
					File: f.Path, Line: idx + 1, Message: "useEffect callback cannot be async (returns a Promise instead of cleanup function)",
					Snippet: trimmed, Remediation: "Define an inner async function inside useEffect and call it.",
				})
			}
		}
	}
	return analyzers.Result{AnalyzerID: "fw-react", Findings: findings}, nil
}

// RegisterAll registers all framework analyzers.
func RegisterAll(reg *analyzers.Registry) {
	reg.Register(FlutterAnalyzer{})
	reg.Register(ReactAnalyzer{})
}
