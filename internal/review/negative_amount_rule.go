package review

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
)

var (
	balanceDebitRe    = regexp.MustCompile(`(?i)\b(?:Balance|balance)\w*\s*(?:[-+]=|=(?:[^\n=;]+[-+]))\s*([^\n;]+)`)
	identOrSelectorRe = regexp.MustCompile(`^[a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*$`)
)

func isIdentOrSelector(s string) bool {
	return identOrSelectorRe.MatchString(s)
}

func buildDebitTargetPattern(raw string) string {
	expr := unwrapDebitOperand(raw)
	tokens := strings.FieldsFunc(expr, func(r rune) bool {
		return r == '*' || r == '/'
	})
	var cleanTokens []string
	for _, tok := range tokens {
		t := unwrapDebitOperand(tok)
		t = strings.TrimSpace(t)
		if isIdentOrSelector(t) {
			cleanTokens = append(cleanTokens, t)
		}
	}

	buildIdentPattern := func(ident string) string {
		parts := strings.Split(ident, ".")
		short := parts[len(parts)-1]
		pat := regexp.QuoteMeta(ident)
		if short != "" && short != ident {
			pat += "|" + regexp.QuoteMeta(short)
		}
		return `(?:` + pat + `)`
	}

	if len(cleanTokens) == 0 {
		return ""
	}
	if len(cleanTokens) == 1 {
		p := buildIdentPattern(cleanTokens[0])
		return `(?:\b` + p + `\b)`
	}
	if len(cleanTokens) == 2 {
		p1 := buildIdentPattern(cleanTokens[0])
		p2 := buildIdentPattern(cleanTokens[1])
		scaled := `(?:` + p1 + `\s*[*x/]\s*` + p2 + `|` + p2 + `\s*[*x/]\s*` + p1 + `)`
		return `(?:\b` + scaled + `\b|\(` + scaled + `\)|\b` + p1 + `\b)`
	}

	var parts []string
	for _, tok := range cleanTokens {
		parts = append(parts, buildIdentPattern(tok))
	}
	return `(?:\b(?:` + strings.Join(parts, `\s*[*x/]\s*`) + `)\b|\b` + parts[0] + `\b)`
}

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

			targetPattern := buildDebitTargetPattern(m[1])
			if targetPattern == "" {
				continue
			}

			compRe := regexp.MustCompile(`(?i)(?:` + targetPattern + `\s*(<=|<|>=|>)\s*([a-zA-Z0-9_.]+)|\b([a-zA-Z0-9_.]+)\s*(<=|<|>=|>)\s*` + targetPattern + `)`)

			hasUpper := false
			hasLower := false
			upperLine := 0

			start := i - 30
			if start < 0 {
				start = 0
			}
			for j := start; j <= i; j++ {
				matches := compRe.FindAllStringSubmatch(lines[j], -1)
				for _, match := range matches {
					var op, operand string
					if match[1] != "" {
						op = match[1]
						operand = match[2]
						isZero := operand == "0" || operand == "1" || strings.EqualFold(operand, "zero")
						if op == ">" || op == ">=" {
							if isZero {
								hasLower = true
							} else if !hasUpper {
								hasUpper = true
								upperLine = block.firstLine + j
							}
						} else if op == "<" || op == "<=" {
							if isZero {
								hasLower = true
							} else if !hasUpper {
								hasUpper = true
								upperLine = block.firstLine + j
							}
						}
					} else if match[4] != "" {
						operand = match[3]
						op = match[4]
						isZero := operand == "0" || operand == "1" || strings.EqualFold(operand, "zero")
						if op == "<" || op == "<=" {
							if isZero {
								hasLower = true
							} else if !hasUpper {
								hasUpper = true
								upperLine = block.firstLine + j
							}
						} else if op == ">" || op == ">=" {
							if isZero {
								hasLower = true
							} else if !hasUpper {
								hasUpper = true
								upperLine = block.firstLine + j
							}
						}
					}
				}
				if hasLower {
					break
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
