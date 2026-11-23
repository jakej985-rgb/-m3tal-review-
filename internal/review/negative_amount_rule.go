package review

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
)

var (
	balanceDebitRe = regexp.MustCompile(`(?i)\b(?:Balance|balance)\w*\s*(?:[-+]=|=(?:[^\n=;]+[-+]))\s*([^\n;]+)`)
)

func unwrapDebitOperand(raw string) string {
	raw = strings.TrimSpace(raw)
	if idx := strings.Index(raw, "//"); idx != -1 {
		raw = strings.TrimSpace(raw[:idx])
	}
	typeCastRe := regexp.MustCompile(`^(?:u?int(?:8|16|32|64)?|float(?:32|64))\s*\((.*)\)$`)
	for {
		raw = strings.TrimSpace(raw)
		if strings.HasPrefix(raw, "(") && strings.HasSuffix(raw, ")") {
			raw = strings.TrimSpace(raw[1 : len(raw)-1])
			continue
		}
		if m := typeCastRe.FindStringSubmatch(raw); len(m) > 1 {
			raw = strings.TrimSpace(m[1])
			continue
		}
		break
	}
	return raw
}

// NegativeAmountRule detects financial transactions and balance modifications where
// an amount is checked against an upper bound or balance limit without ensuring it
// is strictly non-negative (e.g. amount <= 0 check), which allows fund drain via
// negative amount inversion.
type NegativeAmountRule struct {
	ruleRuntime
}

func (r *NegativeAmountRule) Name() string {
	return "negative-amount-bypass"
}

func (r *NegativeAmountRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r *NegativeAmountRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if IsTestOrFixtureFile(block.file) {
			continue
		}
		fileLanguage := (language.CodeChecker{}).Language(block.file)
		if fileLanguage != language.LanguageGo {
			continue
		}

		code := string(maskNonCode(block.file, block.text))
		lines := strings.Split(code, "\n")
		rawLines := strings.Split(block.text, "\n")

		for i, line := range lines {
			lineNum := block.firstLine + i
			m := balanceDebitRe.FindStringSubmatch(line)
			if len(m) < 2 {
				continue
			}

			targetExpr := unwrapDebitOperand(m[1])
			parts := strings.Split(targetExpr, ".")
			shortName := parts[len(parts)-1]

			targetPattern := regexp.QuoteMeta(targetExpr)
			if shortName != "" && shortName != targetExpr {
				targetPattern += "|" + regexp.QuoteMeta(shortName)
			}

			upperCheckRe := regexp.MustCompile(`(?i)\b(?:` + targetPattern + `)\b\s*>\s*(?:[0-9]+|\w+(?:\.\w+)*)`)
			lowerCheckRe := regexp.MustCompile(`(?i)\b(?:` + targetPattern + `)\b\s*(?:<=|<)\s*(?:[01]\b|zero\b)|\b(?:[01]\b|zero\b)\s*(?:>=|>)\s*(?:` + targetPattern + `)\b`)

			hasUpper := false
			hasLower := false
			upperLine := 0

			start := i - 30
			if start < 0 {
				start = 0
			}
			for j := start; j <= i; j++ {
				if lowerCheckRe.MatchString(lines[j]) {
					hasLower = true
					break
				}
				if !hasUpper && upperCheckRe.MatchString(lines[j]) {
					hasUpper = true
					upperLine = block.firstLine + j
				}
			}

			if hasUpper && !hasLower {
				touchesAdded := block.addedLines[lineNum] || (upperLine > 0 && block.addedLines[upperLine])
				if !touchesAdded {
					continue
				}
				key := fmt.Sprintf("%s:%d", block.file, upperLine)
				if seen[key] {
					continue
				}
				seen[key] = true

				lineContent := ""
				idx := upperLine - block.firstLine
				if idx >= 0 && idx < len(rawLines) {
					lineContent = strings.TrimSpace(rawLines[idx])
				}

				findings = append(findings, Finding{
					Rule:        "negative-amount-bypass",
					Severity:    "high",
					Category:    "security",
					File:        block.file,
					Line:        upperLine,
					Snippet:     lineContent,
					Message:     "Upper-bound check on transaction amount without visible non-negative check before balance modification",
					Remediation: "Verify numeric amounts are strictly positive (e.g. amount <= 0 check) in financial and payment transactions to prevent fund drain and credit balance inversion.",
					Confidence:  "High",
				})
			}
		}
	}
	return findings
}
