package review

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	bearerTokenRegex = regexp.MustCompile(`(?i)\b(Bearer\s+)[A-Za-z0-9_\-\.~+/]+=*`)
	privateKeyRegex  = regexp.MustCompile(
		`(?s)-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----`,
	)
	awsKeyRegex    = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	ghTokenRegex   = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{36,}\b`)
	secretAssignRe = regexp.MustCompile(
		`(?i)\b(password|secret|api_key|token|access_key)\s*(?::=|=|:)\s*["'][^"']+["']`,
	)
)

var ruleRationales = map[string]string{
	"code-slop": "Flags code quality defects, maintainability smells, and unused or " +
		"redundant logic.",
	"todo-marker":    "Unresolved task marker left in production source.",
	"debug-leftover": "Debug print or breakpoint left in production source.",
	"hardcoded-credential": "Credential assignment detected; secrets in code risk " +
		"credential leakage.",
	"exposed-secret":      "Known secret token or private key committed to repository.",
	"high-entropy-secret": "High-entropy string matching secret credential heuristics.",
	"path-traversal": "Filesystem path constructed from untrusted input without " +
		"containment checks.",
	"request-taint": "Untrusted request data flows into critical sink without " +
		"sanitization or validation.",
	"resolved-path-write": "Path write targets resolved symlinks where pre-resolution " +
		"checks may be bypassed.",
	"plugin-trust": "Untrusted plugin discovery or execution with elevated environment.",
	"cleartext-transport": "Plain HTTP transport used for sensitive or authenticated " +
		"endpoints.",
	"weak-cryptography": "Broken or non-cryptographic algorithm used for security " +
		"operations.",
	"cross-site-scripting": "User input rendered in unescaped HTML or browser context.",
	"sql-injection":        "SQL query concatenated or formatted with external inputs.",
	"command-injection":    "Operating system command constructed from external inputs.",
	"insecure-tls-verification": "TLS verification explicitly disabled in transport " +
		"configuration.",
	"deadlock":       "Potential lock-order inversion or circular wait condition detected.",
	"race-condition": "Concurrent access to shared memory without mutual exclusion.",
	"typestate":      "Resource state machine transition violated or resource leaked.",
	"touch-target-size": "Interactive UI element has a computed touch target area below the 48x48 dp accessibility minimum.",
	"test-viewport-chrome-contract": "Responsive layout test simulates desktop viewport but omits application shell chrome from boundary constraints.",
	"design-system-spec": "UI implementation violates repository design system guidelines.",
}

// RedactExcerpt removes sensitive credential patterns and bounds excerpt size
// to a maximum of 5 lines and 400 characters.
func RedactExcerpt(text string) string {
	if text == "" {
		return ""
	}

	redacted := privateKeyRegex.ReplaceAllString(text, "[REDACTED PRIVATE KEY]")
	redacted = bearerTokenRegex.ReplaceAllString(redacted, "${1}[REDACTED]")
	redacted = awsKeyRegex.ReplaceAllString(redacted, "[REDACTED AWS KEY]")
	redacted = ghTokenRegex.ReplaceAllString(redacted, "[REDACTED GITHUB TOKEN]")
	redacted = secretAssignRe.ReplaceAllString(redacted, `${1} = "[REDACTED]"`)

	lines := strings.Split(redacted, "\n")
	if len(lines) > 5 {
		lines = lines[:5]
		redacted = strings.Join(lines, "\n") + "\n..."
	}
	if len(redacted) > 400 {
		redacted = redacted[:397] + "..."
	}
	return redacted
}

func parseStepKind(lowerMsg string) string {
	prefixes := []string{"source", "sink", "call", "branch", "state", "lock"}
	for _, p := range prefixes {
		if strings.HasPrefix(lowerMsg, p) {
			return p
		}
	}
	return "note"
}

func parseEvidenceSteps(f Finding) ([]ExplainedStep, string, []string) {
	steps := make([]ExplainedStep, 0, len(f.Evidence))
	var inferences []string
	hasSource, hasSink := false, false

	for i, ev := range f.Evidence {
		msg := ev.Message
		lowerMsg := strings.ToLower(msg)
		isInference := strings.HasPrefix(lowerMsg, "inference") ||
			strings.HasPrefix(lowerMsg, "inferred") ||
			strings.Contains(lowerMsg, "heuristic")
		if isInference {
			inferences = append(inferences, msg)
		}

		kind := parseStepKind(lowerMsg)
		if kind == "source" {
			hasSource = true
		} else if kind == "sink" {
			hasSink = true
		}

		loc := ""
		if ev.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, ev.Line)
		}

		steps = append(steps, ExplainedStep{
			StepNumber:  i + 1,
			Kind:        kind,
			Location:    loc,
			Statement:   msg,
			IsInference: isInference,
		})
	}

	if f.Snippet != "" && len(steps) > 0 {
		steps[len(steps)-1].Snippet = RedactExcerpt(f.Snippet)
	}

	evidenceKind := "pattern-match"
	if tKind := f.Metadata["analysis_trace"]; tKind != "" {
		evidenceKind = tKind
	} else if hasSource && hasSink {
		evidenceKind = "source-to-sink"
	} else if len(steps) > 1 {
		evidenceKind = "trace"
	}

	return steps, evidenceKind, inferences
}

func buildSeverityFactors(f Finding) string {
	if f.Risk != nil {
		return fmt.Sprintf(
			"Severity '%s' with risk score %.1f (%s).",
			f.Severity, f.RiskScore, f.Risk.Explanation,
		)
	}
	return fmt.Sprintf("Severity '%s' derived from vulnerability classification.", f.Severity)
}

func buildConfidenceRationale(conf string) string {
	if conf == "" {
		return "Confidence unstated; defaulting to standard heuristic confidence."
	}
	return fmt.Sprintf("Confidence '%s': verified against pattern syntax or trace.", conf)
}

func collectAssumptions(meta map[string]string) []string {
	var assumptions []string
	if raw := meta["analysis_assumptions"]; raw != "" {
		for _, a := range strings.Split(raw, ";") {
			if a = strings.TrimSpace(a); a != "" {
				assumptions = append(assumptions, a)
			}
		}
	}
	return assumptions
}

func collectLimitations(f Finding) []string {
	var limitations []string
	if f.Metadata["analysis_truncated"] == "true" {
		reasons := f.Metadata["analysis_truncation_reasons"]
		if reasons == "" {
			reasons = "budget or step threshold exceeded"
		}
		limitations = append(limitations, "Analysis truncated: "+reasons)
	}
	if strings.EqualFold(f.Reachability, "unknown") {
		limitations = append(
			limitations,
			"Reachability could not be statically verified; conservative factor applied.",
		)
	}
	return limitations
}

func buildPrioritizationNote(f Finding) string {
	if f.RiskScore <= 0 {
		return ""
	}
	note := fmt.Sprintf("Ranked with risk score %.1f.", f.RiskScore)
	if f.CorrelationID != "" {
		note += fmt.Sprintf(" Correlated under cluster '%s'.", f.CorrelationID)
	}
	return note
}

// ExplainFinding generates a deterministic, evidence-grounded explanation for a finding.
func ExplainFinding(f Finding) *FindingExplanation {
	rationale := ruleRationales[f.Rule]
	if rationale == "" {
		rationale = fmt.Sprintf("Rule '%s' flagged matching pattern in %s.", f.Rule, f.File)
	}

	steps, evidenceKind, inferences := parseEvidenceSteps(f)
	summary := fmt.Sprintf("Direct pattern match at %s:%d.", f.File, f.Line)
	if len(steps) > 0 {
		summary = fmt.Sprintf(
			"Evidence trace (%s) contains %d step(s) in %s.",
			evidenceKind, len(steps), f.File,
		)
	}

	return &FindingExplanation{
		RuleRationale:       rationale,
		EvidenceSummary:     summary,
		EvidenceKind:        evidenceKind,
		EvidenceSteps:       steps,
		SeverityFactors:     buildSeverityFactors(f),
		ConfidenceRationale: buildConfidenceRationale(f.Confidence),
		Assumptions:         collectAssumptions(f.Metadata),
		Limitations:         collectLimitations(f),
		PrioritizationNote:  buildPrioritizationNote(f),
		Inferences:          inferences,
	}
}

// FormatExplanationMarkdown formats a finding explanation into clean Markdown.
func FormatExplanationMarkdown(exp *FindingExplanation) string {
	if exp == nil {
		return ""
	}

	var b strings.Builder
	if exp.RuleRationale != "" {
		fmt.Fprintf(&b, "**Rationale:** %s\n\n", exp.RuleRationale)
	}
	if exp.EvidenceSummary != "" {
		fmt.Fprintf(&b, "**Evidence (%s):** %s\n", exp.EvidenceKind, exp.EvidenceSummary)
	}
	if len(exp.EvidenceSteps) > 0 {
		b.WriteString("\n| # | Kind | Location | Statement |\n|---|---|---|---|\n")
		for _, s := range exp.EvidenceSteps {
			inferenceMark := ""
			if s.IsInference {
				inferenceMark = " *(inference)*"
			}
			stmt := strings.ReplaceAll(s.Statement, "|", "\\|")
			fmt.Fprintf(
				&b, "| %d | `%s` | `%s` | %s%s |\n",
				s.StepNumber, s.Kind, s.Location, stmt, inferenceMark,
			)
		}
		b.WriteString("\n")
	}
	if exp.SeverityFactors != "" {
		fmt.Fprintf(&b, "- **Severity Factors:** %s\n", exp.SeverityFactors)
	}
	if exp.ConfidenceRationale != "" {
		fmt.Fprintf(&b, "- **Confidence:** %s\n", exp.ConfidenceRationale)
	}
	if len(exp.Assumptions) > 0 {
		fmt.Fprintf(&b, "- **Assumptions:** %s\n", strings.Join(exp.Assumptions, "; "))
	}
	if len(exp.Limitations) > 0 {
		fmt.Fprintf(&b, "- **Limitations:** %s\n", strings.Join(exp.Limitations, "; "))
	}
	if exp.PrioritizationNote != "" {
		fmt.Fprintf(&b, "- **Prioritization:** %s\n", exp.PrioritizationNote)
	}
	return strings.TrimSpace(b.String())
}
