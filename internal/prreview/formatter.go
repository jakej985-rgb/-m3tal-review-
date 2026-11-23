package prreview

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/repair"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// ReviewVerdict represents GitHub PR review decision.
type ReviewVerdict string

const (
	VerdictApprove        ReviewVerdict = "APPROVE"
	VerdictRequestChanges ReviewVerdict = "REQUEST_CHANGES"
	VerdictComment        ReviewVerdict = "COMMENT"
)

// InlineComment represents an individual line-level review comment for a PR diff.
type InlineComment struct {
	Path        string `json:"path"`
	Line        int    `json:"line"`
	Side        string `json:"side"` // "RIGHT" for new file lines
	Position    int    `json:"position,omitempty"`
	Body        string `json:"body"`
	Severity    string `json:"severity"`
	Rule        string `json:"rule"`
	HasFixPatch bool   `json:"has_fix_patch"`
}

// PRReviewReport packages the synthesized overview, inline comments, and decision metrics.
type PRReviewReport struct {
	SummaryMarkdown string             `json:"summary_markdown"`
	InlineComments  []InlineComment    `json:"inline_comments"`
	Verdict         ReviewVerdict      `json:"verdict"`
	Grade           review.GradeResult `json:"grade"`
	TotalFindings   int                `json:"total_findings"`
	CriticalCount   int                `json:"critical_count"`
	HighCount       int                `json:"high_count"`
	MediumCount     int                `json:"medium_count"`
	LowCount        int                `json:"low_count"`
	SuggestionCount int                `json:"suggestion_count"`
	Synthesis       *PRSynthesis       `json:"synthesis,omitempty"`
}

// FormatOptions configures report generation.
type FormatOptions struct {
	CommentOnly bool
	RepoRoot    string
}

const SummaryMarkerTag = "<!-- m3tal-review:summary -->"

// GeneratePRReview processes findings and git diffs to generate a comprehensive AI-like review.
func GeneratePRReview(findings []review.Finding, fileDiffs []*FileDiff, opts FormatOptions) (*PRReviewReport, error) {
	grade := review.ComputeGrade(findings)
	diffMap := make(map[string]*FileDiff)
	for _, fd := range fileDiffs {
		if fd.NewPath != "" {
			diffMap[fd.NewPath] = fd
		}
		if fd.OldPath != "" {
			diffMap[fd.OldPath] = fd
		}
	}

	readFile := func(path string) ([]byte, error) {
		if opts.RepoRoot != "" {
			return os.ReadFile(filepath.Join(opts.RepoRoot, path))
		}
		return os.ReadFile(path)
	}

	synthesis := SynthesizeChanges(fileDiffs, readFile)

	report := &PRReviewReport{
		Grade:         grade,
		TotalFindings: len(findings),
		Synthesis:     synthesis,
	}

	for _, f := range findings {
		switch strings.ToLower(f.Severity) {
		case "critical":
			report.CriticalCount++
		case "high":
			report.HighCount++
		case "medium":
			report.MediumCount++
		case "low", "info":
			report.LowCount++
		}
	}

	// Compute Review Verdict
	if opts.CommentOnly {
		report.Verdict = VerdictComment
	} else if report.CriticalCount > 0 || report.HighCount > 0 {
		report.Verdict = VerdictRequestChanges
	} else if report.MediumCount > 0 {
		report.Verdict = VerdictComment
	} else {
		report.Verdict = VerdictApprove
	}

	// Separate findings:
	// Critical & High -> inline comments on PR diff lines (if mapped)
	// Medium, Low, Nits -> collapsible summary in top-level overview
	var inlineComments []InlineComment
	var summaryFindings []review.Finding

	for _, f := range findings {
		isHighSeverity := strings.ToLower(f.Severity) == "critical" || strings.ToLower(f.Severity) == "high"
		cleanPath := filepath.Clean(f.File)
		fd := diffMap[f.File]
		if fd == nil {
			fd = diffMap[cleanPath]
		}

		pos := 0
		if fd != nil && f.Line > 0 {
			pos = fd.FindPositionForLine(f.Line)
		}

		// Check if finding maps to a diff line in this PR (pos > 0 guarantees it is within a diff hunk)
		if isHighSeverity && pos > 0 {
			// Generate inline comment body with suggestion if possible
			commentBody, hasSuggestion := buildInlineCommentBody(f, opts.RepoRoot)
			if hasSuggestion {
				report.SuggestionCount++
			}
			inlineComments = append(inlineComments, InlineComment{
				Path:        f.File,
				Line:        f.Line,
				Side:        "RIGHT",
				Position:    pos,
				Body:        commentBody,
				Severity:    f.Severity,
				Rule:        f.Rule,
				HasFixPatch: hasSuggestion,
			})
		} else {
			summaryFindings = append(summaryFindings, f)
		}
	}
	report.InlineComments = inlineComments

	// Build top-level summary markdown
	report.SummaryMarkdown = buildSummaryMarkdown(report, synthesis, summaryFindings)
	return report, nil
}

func buildInlineCommentBody(f review.Finding, repoRoot string) (string, bool) {
	var b strings.Builder

	fmt.Fprintf(&b, "### ⚠️ Finding: `%s`\n", f.Rule)
	fmt.Fprintf(&b, "**Severity:** `%s` | **Confidence:** `%s`\n\n",
		strings.ToUpper(f.Severity), strings.ToUpper(f.Confidence))
	fmt.Fprintf(&b, "%s\n\n", f.Message)

	// Rationale
	rationale := ""
	if f.Explanation != nil && f.Explanation.RuleRationale != "" {
		rationale = f.Explanation.RuleRationale
	} else if f.Remediation != "" {
		rationale = f.Remediation
	}
	if rationale != "" {
		fmt.Fprintf(&b, "> **Deterministic Rationale:**\n> %s\n\n", rationale)
	}

	// Suggestion generation
	fixer := repair.FindFixerForFinding(f)
	if fixer != nil {
		var content []byte
		if repoRoot != "" {
			content, _ = os.ReadFile(filepath.Join(repoRoot, f.File))
		}
		if len(content) == 0 && f.Snippet != "" {
			content = []byte(f.Snippet)
		}
		if len(content) > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			prop, err := fixer.GenerateProposal(ctx, repoRoot, f, content)
			cancel()
			if err == nil && prop != nil {
				sug := extractSuggestionFromPatch(prop.Patch, f.Line)
				if sug != "" {
					b.WriteString("#### 💡 Suggested Fix\n")
					b.WriteString("```suggestion\n")
					b.WriteString(sug)
					if !strings.HasSuffix(sug, "\n") {
						b.WriteString("\n")
					}
					b.WriteString("```\n")
					return b.String(), true
				}
			}
		}
	}

	if f.Remediation != "" {
		fmt.Fprintf(&b, "**Remediation Guidance:**\n```\n%s\n```\n", f.Remediation)
	}

	return b.String(), false
}

func buildSummaryMarkdown(report *PRReviewReport, synthesis *PRSynthesis, remainingFindings []review.Finding) string {
	var b strings.Builder

	// Hidden marker tag for in-place comment updates
	b.WriteString(SummaryMarkerTag + "\n")

	// Header
	verdictEmoji := "✅"
	verdictText := "Approved"
	switch report.Verdict {
	case VerdictRequestChanges:
		verdictEmoji = "❌"
		verdictText = "Changes Requested"
	case VerdictComment:
		verdictEmoji = "⚠️"
		verdictText = "Review Comments"
	}

	b.WriteString("# 🛡️ m3tal-review PR Assessment\n\n")

	// Key Metrics Table
	b.WriteString("| Verdict | Quality Grade | Total Findings | Critical | High | Medium | Low/Style | Suggestions |\n")
	b.WriteString("| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n")
	fmt.Fprintf(&b, "| %s **%s** | **%s** (%d/100) | %d | %d | %d | %d | %d | %d |\n\n",
		verdictEmoji, verdictText, report.Grade.Grade, report.Grade.Score,
		report.TotalFindings, report.CriticalCount, report.HighCount, report.MediumCount, report.LowCount,
		report.SuggestionCount,
	)

	// Executive Walkthrough & Summary
	b.WriteString("## 🔎 Walkthrough & Impact\n\n")
	if synthesis != nil && synthesis.Overview != "" {
		b.WriteString(synthesis.Overview + "\n")
	}

	// Architectural Taxonomy Breakdown Table
	b.WriteString("### 📐 Component Walkthrough\n\n")
	b.WriteString("| Component | File | Modifications & Symbols | Risk |\n")
	b.WriteString("| :--- | :--- | :--- | :--- |\n")

	categories := []TaxonomyCategory{
		TaxonomyArchAndAPI,
		TaxonomyCoreLogic,
		TaxonomySecurityAndAuth,
		TaxonomyDepsAndConfig,
		TaxonomyTestsAndTooling,
	}

	for _, cat := range categories {
		files := synthesis.TaxonomyGroups[cat]
		if len(files) == 0 {
			continue
		}
		for _, f := range files {
			riskBadge := fmt.Sprintf("`%s`", f.Risk)
			if f.Risk == "High" {
				riskBadge = "🚨 **High**"
			} else if f.Risk == "Moderate" {
				riskBadge = "⚡ **Moderate**"
			}
			fmt.Fprintf(&b, "| **%s** | `%s` | %s (+%d/-%d) | %s |\n",
				cat, f.Path, f.SummaryText, f.Additions, f.Deletions, riskBadge)
		}
	}
	b.WriteString("\n")

	// Actionable Review Checklist
	b.WriteString("## 📋 Review Checklist\n\n")
	if report.CriticalCount == 0 && report.HighCount == 0 {
		b.WriteString("- [x] **Zero Critical/High Defects:** No blocking security or correctness vulnerabilities.\n")
	} else {
		fmt.Fprintf(&b, "- [ ] **Remediate High-Severity Issues:** %d critical/high issue(s) require resolution.\n",
			report.CriticalCount+report.HighCount)
	}
	if report.SuggestionCount > 0 {
		fmt.Fprintf(&b, "- [ ] **Apply 1-Click Suggestions:** %d automated inline suggestion(s) ready to commit.\n",
			report.SuggestionCount)
	}
	b.WriteString("- [x] **Deterministic Static Gate:** Evaluated without non-deterministic AI hallucinations.\n\n")

	// Collapsible Lower Severity Findings (to prevent notification spam)
	if len(remainingFindings) > 0 {
		hasHigh := false
		for _, rf := range remainingFindings {
			s := strings.ToLower(rf.Severity)
			if s == "critical" || s == "high" {
				hasHigh = true
				break
			}
		}
		summaryTitle := fmt.Sprintf("Code Quality, Style & Minor Findings (%d)", len(remainingFindings))
		if hasHigh {
			summaryTitle = fmt.Sprintf("Additional Findings & Non-Diff Issues (%d)", len(remainingFindings))
		}
		fmt.Fprintf(&b, "<details>\n<summary><b>%s</b></summary>\n\n", summaryTitle)
		b.WriteString("| Severity | Rule | Location | Message |\n")
		b.WriteString("| :--- | :--- | :--- | :--- |\n")
		for _, rf := range remainingFindings {
			loc := rf.File
			if rf.Line > 0 {
				loc = fmt.Sprintf("%s:%d", rf.File, rf.Line)
			}
			msg := strings.ReplaceAll(rf.Message, "|", "\\|")
			if len(msg) > 90 {
				msg = msg[:87] + "..."
			}
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | %s |\n",
				strings.ToUpper(rf.Severity), rf.Rule, loc, msg)
		}
		b.WriteString("\n</details>\n\n")
	}

	b.WriteString("---\n<sub>Generated by m3tal-review deterministic offline engine. Zero external AI calls.</sub>\n")
	return b.String()
}

func extractSuggestionFromPatch(patch string, targetLine int) string {
	lines := strings.Split(patch, "\n")
	type hunk struct {
		startLine int
		lineCount int
		additions []string
	}

	var hunks []hunk
	var currentHunk *hunk

	for _, l := range lines {
		if strings.HasPrefix(l, "@@ ") {
			if currentHunk != nil {
				hunks = append(hunks, *currentHunk)
			}
			currentHunk = &hunk{startLine: targetLine, lineCount: 1}
			parts := strings.Split(l, " ")
			if len(parts) >= 3 && strings.HasPrefix(parts[1], "-") {
				sub := strings.TrimPrefix(parts[1], "-")
				nums := strings.Split(sub, ",")
				origStart, _ := strconv.Atoi(nums[0])
				origCount := 1
				if len(nums) > 1 {
					origCount, _ = strconv.Atoi(nums[1])
				}
				currentHunk.startLine = origStart
				currentHunk.lineCount = origCount
			}
			continue
		}
		if currentHunk != nil {
			if strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "+++") {
				currentHunk.additions = append(currentHunk.additions, strings.TrimPrefix(l, "+"))
			}
		}
	}
	if currentHunk != nil {
		hunks = append(hunks, *currentHunk)
	}

	if len(hunks) == 0 {
		return ""
	}

	for _, h := range hunks {
		if targetLine >= h.startLine && targetLine <= h.startLine+h.lineCount {
			if len(h.additions) > 0 {
				return strings.Join(h.additions, "\n")
			}
		}
	}

	for _, h := range hunks {
		if len(h.additions) > 0 {
			return strings.Join(h.additions, "\n")
		}
	}

	return ""
}
