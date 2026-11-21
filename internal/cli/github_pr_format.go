package cli

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

// formatFindingsGitHubPR generates a GitHub PR review markdown report from a slice of findings.
func formatFindingsGitHubPR(findings []review.Finding, repoRoot string) (string, error) {
	grade := review.ComputeGrade(findings)
	report := review.Report{
		Scope:     "staged",
		Timestamp: time.Now().UTC(),
		Findings:  findings,
		Grade:     &grade,
	}
	passed := true
	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "high" {
			passed = false
			break
		}
	}
	report.Passed = passed
	return formatReportGitHubPR(report, repoRoot)
}

// formatReportGitHubPR produces a Devin-style GitHub PR review markdown report
// including summary tables, deterministic rationales, and inline ```suggestion``` blocks.
func formatReportGitHubPR(report review.Report, repoRoot string) (string, error) {
	var b strings.Builder

	sevCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range report.Findings {
		sevCounts[strings.ToLower(f.Severity)]++
	}

	verdictEmoji := "✅"
	verdictText := "Passed"
	if !report.Passed || sevCounts["critical"] > 0 || sevCounts["high"] > 0 {
		verdictEmoji = "❌"
		verdictText = "Changes Requested"
	} else if sevCounts["medium"] > 0 {
		verdictEmoji = "⚠️"
		verdictText = "Warnings Detected"
	}

	gradeLetter := "A+"
	gradeScore := 100
	if report.Grade != nil {
		gradeLetter = report.Grade.Grade
		gradeScore = report.Grade.Score
	}

	// Pre-generate proposals and suggestions for all findings
	type findingItem struct {
		finding    review.Finding
		suggestion string
		fixerName  string
	}
	items := make([]findingItem, 0, len(report.Findings))
	suggestionCount := 0

	for _, f := range report.Findings {
		item := findingItem{finding: f}
		fixer := repair.FindFixerForFinding(f)
		if fixer != nil {
			item.fixerName = fixer.Name()
			var content []byte
			if repoRoot != "" {
				target := filepath.Join(repoRoot, f.File)
				content, _ = os.ReadFile(target)
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
						item.suggestion = sug
						suggestionCount++
					}
				}
			}
		}
		items = append(items, item)
	}

	// 1. Header & Summary Verdict Table
	b.WriteString("# 🛡️ m3tal-review PR Report\n\n")
	b.WriteString("| Verdict | Grade | Total Findings | Critical | High | Medium | Low | Suggestions |\n")
	b.WriteString("| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n")
	fmt.Fprintf(&b, "| %s **%s** | **%s** (%d/100) | %d | %d | %d | %d | %d | %d |\n\n",
		verdictEmoji, verdictText, gradeLetter, gradeScore,
		len(report.Findings),
		sevCounts["critical"], sevCounts["high"], sevCounts["medium"], sevCounts["low"]+sevCounts["info"],
		suggestionCount,
	)

	if len(report.Findings) == 0 {
		b.WriteString("No quality, security, or lifecycle issues detected in reviewed files.\n")
		return b.String(), nil
	}

	// 2. Overview Table
	b.WriteString("## 📋 Findings Overview\n\n")
	b.WriteString("| Severity | Rule | Location | Message | Suggestion |\n")
	b.WriteString("| :--- | :--- | :--- | :--- | :---: |\n")
	for _, it := range items {
		f := it.finding
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		msg := strings.ReplaceAll(f.Message, "|", "\\|")
		if len(msg) > 90 {
			msg = msg[:87] + "..."
		}
		sugStatus := "—"
		if it.suggestion != "" {
			sugStatus = "💡 Available"
		} else if it.fixerName != "" {
			sugStatus = "🔧 Fixable"
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | %s | %s |\n",
			strings.ToUpper(f.Severity), f.Rule, loc, msg, sugStatus)
	}
	b.WriteString("\n")

	// 3. Detailed Findings & Inline Suggestions
	b.WriteString("## 🔍 Detailed Review & Suggestions\n\n")
	for i, it := range items {
		f := it.finding
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		fmt.Fprintf(&b, "### %d. [%s] `%s` at `%s`\n\n", i+1, strings.ToUpper(f.Severity), f.Rule, loc)
		fmt.Fprintf(&b, "- **Message:** %s\n", f.Message)
		if f.Category != "" {
			fmt.Fprintf(&b, "- **Category:** `%s`\n", f.Category)
		}
		if f.Confidence != "" {
			fmt.Fprintf(&b, "- **Confidence:** `%s`\n", f.Confidence)
		}

		// Rationale
		rationale := ""
		if f.Explanation != nil && f.Explanation.RuleRationale != "" {
			rationale = f.Explanation.RuleRationale
		} else if f.Remediation != "" {
			rationale = f.Remediation
		}
		if rationale != "" {
			fmt.Fprintf(&b, "\n> **Deterministic Rationale:**\n> %s\n\n", rationale)
		}

		// Inline Suggestion Block or Remediation
		if it.suggestion != "" {
			b.WriteString("#### 💡 Proposed Suggestion\n")
			b.WriteString("```suggestion\n")
			b.WriteString(it.suggestion)
			if !strings.HasSuffix(it.suggestion, "\n") {
				b.WriteString("\n")
			}
			b.WriteString("```\n\n")
		} else if f.Remediation != "" {
			fmt.Fprintf(&b, "**Remediation:** %s\n\n", f.Remediation)
		}
	}

	b.WriteString("---\n<sub>Generated by m3tal-review deterministic offline engine. Zero external AI calls.</sub>\n")
	return b.String(), nil
}

// extractSuggestionFromPatch parses a unified diff patch and extracts the replacement
// additions for the hunk covering targetLine.
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
			// Parse @@ -origStart,origLen +newStart,newLen @@
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

	// Match hunk by line number
	for _, h := range hunks {
		if targetLine >= h.startLine && targetLine <= h.startLine+h.lineCount {
			if len(h.additions) > 0 {
				return strings.Join(h.additions, "\n")
			}
		}
	}

	// Fallback to first hunk with additions
	for _, h := range hunks {
		if len(h.additions) > 0 {
			return strings.Join(h.additions, "\n")
		}
	}

	return ""
}
