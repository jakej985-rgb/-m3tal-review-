package review

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
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

func isNumericLiteral(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

func isZeroOrOneThreshold(s string) bool {
	s = strings.TrimSpace(s)
	if strings.EqualFold(s, "zero") {
		return true
	}
	if val, err := strconv.ParseFloat(s, 64); err == nil {
		if val == 0.0 || val == 1.0 {
			return true
		}
	}
	return false
}

func blockExits(lines []string, start, end int) bool {
	for k := start; k <= end && k < len(lines); k++ {
		trimmed := strings.TrimSpace(lines[k])
		if strings.HasPrefix(trimmed, "return") ||
			strings.HasPrefix(trimmed, "panic(") {
			return true
		}
	}
	return false
}

func hasExitingElse(lines []string, endIfLine int) bool {
	elseStart := -1
	for k := endIfLine; k < len(lines) && k <= endIfLine+2; k++ {
		if strings.Contains(lines[k], "else") {
			elseStart = k
			break
		}
	}
	if elseStart == -1 {
		return false
	}
	elseEnd := findIfBlockEnd(lines, elseStart)
	return blockExits(lines, elseStart, elseEnd)
}

func getIfCondition(lines []string, j int) string {
	start := j
	for k := j; k >= 0 && k >= j-5; k-- {
		if strings.Contains(lines[k], "if ") || strings.Contains(lines[k], "if(") {
			start = k
			break
		}
	}
	var condParts []string
	for k := start; k < len(lines) && k <= start+5; k++ {
		condParts = append(condParts, lines[k])
		if strings.Contains(lines[k], "{") {
			break
		}
	}
	full := strings.Join(condParts, " ")
	if idx := strings.Index(full, "if "); idx != -1 {
		full = full[idx+3:]
	} else if idx := strings.Index(full, "if("); idx != -1 {
		full = full[idx+2:]
	}
	if semi := strings.LastIndex(full, ";"); semi != -1 {
		full = full[semi+1:]
	}
	if idx := strings.Index(full, "{"); idx != -1 {
		full = full[:idx]
	}
	return full
}

func unwrapOuterParens(s string) string {
	s = strings.TrimSpace(s)
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		depth := 0
		matched := true
		for i, r := range s {
			if r == '(' {
				depth++
			} else if r == ')' {
				depth--
				if depth == 0 && i < len(s)-1 {
					matched = false
					break
				}
			}
		}
		if matched && depth == 0 {
			s = strings.TrimSpace(s[1 : len(s)-1])
		} else {
			break
		}
	}
	return s
}

func splitTopLevelOr(s string) []string {
	var terms []string
	depth := 0
	start := 0
	n := len(s)
	for i := 0; i < n; i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case '|':
			if depth == 0 && i+1 < n && s[i+1] == '|' {
				terms = append(terms, s[start:i])
				start = i + 2
				i++
			}
		}
	}
	terms = append(terms, s[start:])
	return terms
}

func isRejectionClauseUnconjoined(ifCond, compSnippet string) bool {
	s := unwrapOuterParens(ifCond)
	if !strings.Contains(s, "&&") {
		return true
	}
	terms := splitTopLevelOr(s)
	if len(terms) > 1 {
		for _, term := range terms {
			t := unwrapOuterParens(term)
			if strings.Contains(t, compSnippet) {
				if isRejectionClauseUnconjoined(t, compSnippet) {
					return true
				}
			}
		}
		return false
	}
	return false
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
		if isIdentOrSelector(t) || isNumericLiteral(t) {
			cleanTokens = append(cleanTokens, t)
		}
	}

	hasIdent := false
	var identToken string
	for _, tok := range cleanTokens {
		if isIdentOrSelector(tok) && !isNumericLiteral(tok) {
			if !hasIdent {
				identToken = tok
				hasIdent = true
			}
		}
	}
	if !hasIdent {
		return ""
	}

	buildIdentPattern := func(ident string) string {
		if isNumericLiteral(ident) {
			base := strings.TrimSuffix(ident, ".0")
			return `(?:` + regexp.QuoteMeta(ident) + `|` + regexp.QuoteMeta(base) + `(?:\.0+)?)`
		}
		parts := strings.Split(ident, ".")
		short := parts[len(parts)-1]
		pat := regexp.QuoteMeta(ident)
		if short != "" && short != ident {
			pat += "|" + regexp.QuoteMeta(short)
		}
		return `(?:` + pat + `)`
	}

	fallbackPat := buildIdentPattern(identToken)

	if len(cleanTokens) == 1 {
		p := buildIdentPattern(cleanTokens[0])
		return `(?:\b` + p + `\b)`
	}
	if len(cleanTokens) == 2 {
		p1 := buildIdentPattern(cleanTokens[0])
		p2 := buildIdentPattern(cleanTokens[1])
		scaled := `(?:` + p1 + `\s*[*x/]\s*` + p2 + `|` + p2 + `\s*[*x/]\s*` + p1 + `)`
		return `(?:\b` + scaled + `\b|\(` + scaled + `\)|\b` + fallbackPat + `\b)`
	}

	var parts []string
	for _, tok := range cleanTokens {
		parts = append(parts, buildIdentPattern(tok))
	}
	return `(?:\b(?:` + strings.Join(parts, `\s*[*x/]\s*`) + `)\b|\b` + fallbackPat + `\b)`
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
					var isLeftTarget bool
					if match[1] != "" {
						op = match[1]
						operand = match[2]
						isLeftTarget = true
					} else if match[4] != "" {
						operand = match[3]
						op = match[4]
						isLeftTarget = false
					} else {
						continue
					}

					isZero := isZeroOrOneThreshold(operand)
					var checkType int // 0: upper check, 1: positive check, 2: rejection check

					if isLeftTarget {
						if op == ">" || op == ">=" {
							if isZero {
								checkType = 1 // target > 0
							} else {
								checkType = 0 // target > balance
							}
						} else if op == "<" || op == "<=" {
							if isZero {
								checkType = 2 // target <= 0
							} else {
								checkType = 0 // target < balance
							}
						}
					} else { // operand OP target
						if op == "<" || op == "<=" {
							if isZero {
								checkType = 1 // 0 < target
							} else {
								checkType = 0 // balance < target
							}
						} else if op == ">" || op == ">=" {
							if isZero {
								checkType = 2 // 0 >= target
							} else {
								checkType = 0 // balance > target
							}
						}
					}

					if checkType == 0 {
						if !hasUpper {
							hasUpper = true
							upperLine = block.firstLine + j
						}
					} else {
						endBlock := findIfBlockEnd(lines, j)
						if checkType == 1 {
							// Positive check: protects only if debit is inside the branch
							// or an else branch exits before the debit
							if i <= endBlock || hasExitingElse(lines, endBlock) {
								hasLower = true
							}
						} else if checkType == 2 {
							// Rejection check: protects if the block exits early and the rejection clause for target is not conjoined with &&
							ifCond := getIfCondition(lines, j)
							if isRejectionClauseUnconjoined(ifCond, match[0]) {
								if i > endBlock && blockExits(lines, j, endBlock) {
									hasLower = true
								} else if i <= endBlock && j == i && strings.Contains(lines[j], "return") {
									// Same-line guard: if amount <= 0 { return }
									hasLower = true
								}
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
