package review

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

// TouchTargetRule is a symbolic layout geometry analyzer that verifies interactive
// UI elements meet minimum touch target dimensions (48x48 dp per WCAG 2.5.5,
// Android Material, iOS HIG, and repository design systems) without requiring AI.
type TouchTargetRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (TouchTargetRule) Name() string {
	return "touch-target-size"
}

func (r TouchTargetRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

// Regex patterns for interactive widgets and layout attributes
var (
	// Interactive wrapper widgets
	inkWellRe        = regexp.MustCompile(`\b(InkWell|GestureDetector|InkResponse)\s*\(`)
	textButtonRe     = regexp.MustCompile(`\b(TextButton|OutlinedButton|ElevatedButton)\s*\(`)
	iconButtonRe     = regexp.MustCompile(`\bIconButton\s*\(`)

	// Explicit shrinkWrap anti-pattern
	shrinkWrapRe     = regexp.MustCompile(`\btapTargetSize:\s*MaterialTapTargetSize\.shrinkWrap\b`)
	minimumSizeZero  = regexp.MustCompile(`\bminimumSize:\s*(?:Size\.zero|const\s+Size\(0,\s*0\)|Size\(0,\s*0\))\b`)

	// Size/padding extraction
	paddingVerticalRe = regexp.MustCompile(`\bvertical:\s*([0-9.]+)`)
	paddingAllRe      = regexp.MustCompile(`\bEdgeInsets\.all\(\s*([0-9.]+)\s*\)`)
	paddingSymmetricV = regexp.MustCompile(`\bEdgeInsets\.symmetric\([^)]*vertical:\s*([0-9.]+)`)
	iconSizeRe        = regexp.MustCompile(`\b(?:Icon|MonsterIcon)\s*\([^)]*size:\s*([0-9.]+)`)
	containerHeightRe = regexp.MustCompile(`\b(?:Container|SizedBox)\s*\([^)]*height:\s*([0-9.]+)`)
	fontSizeRe        = regexp.MustCompile(`\bfontSize:\s*([0-9.]+)`)
	childVariableRe   = regexp.MustCompile(`\bchild:\s*([a-z]\w*)`)
	anyIconRe         = regexp.MustCompile(`\bIcon\s*\(`)

	// Constraint overrides that satisfy the 48dp floor
	minConstraint48Re = regexp.MustCompile(`\b(?:minHeight:\s*(?:4[8-9]|[5-9]\d|\d{3,})|minWidth:\s*(?:4[8-9]|[5-9]\d|\d{3,})|kMinInteractiveDimension|height:\s*(?:4[8-9]|[5-9]\d|\d{3,}))\b`)
)

func (r TouchTargetRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	// Locate design system citation if available
	designDocCitation := r.findDesignSystemTouchTargetCitation()

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		// Only check UI files (e.g. Flutter .dart, React .tsx/.jsx) and exclude test files
		filePath := fileDiff.Path
		if !isUIFile(filePath) || isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		for _, block := range blocks {
			findings = append(findings, r.checkBlock(block, seen, designDocCitation)...)
		}
	}

	return findings
}

func isUIFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".dart") ||
		strings.HasSuffix(lower, ".tsx") ||
		strings.HasSuffix(lower, ".jsx") ||
		strings.HasSuffix(lower, ".vue") ||
		strings.HasSuffix(lower, ".svelte")
}

func isTestFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, "_test.go") ||
		strings.HasSuffix(lower, "_test.dart") ||
		strings.HasSuffix(lower, "_test.rs") ||
		strings.HasSuffix(lower, "_test.py") ||
		strings.HasSuffix(lower, "test.js") ||
		strings.HasSuffix(lower, "test.ts") ||
		strings.HasSuffix(lower, ".test.tsx") ||
		strings.HasSuffix(lower, ".spec.tsx") ||
		strings.HasSuffix(lower, ".test.jsx") ||
		strings.HasSuffix(lower, ".spec.jsx") ||
		strings.HasSuffix(lower, "_test.cpp") ||
		strings.HasSuffix(lower, "_test.cc") ||
		strings.HasSuffix(lower, "_test.c") ||
		strings.HasSuffix(lower, "test.java") ||
		strings.HasSuffix(lower, "test.kt") ||
		strings.Contains(lower, "/test/") ||
		strings.Contains(lower, "/tests/")
}

func (r TouchTargetRule) checkBlock(block diffSourceBlock, seen map[string]bool, citation string) []Finding {
	var findings []Finding

	// Check 1: Explicit shrinkWrap + minimumSize.zero on buttons (e.g. TextButton)
	findings = append(findings, r.checkShrinkWrapButtons(block, seen, citation)...)

	// Check 2: InkWell / GestureDetector wrapping small children without min constraints
	findings = append(findings, r.checkInteractiveWrappers(block, seen, citation)...)

	return findings
}

func (r TouchTargetRule) checkShrinkWrapButtons(block diffSourceBlock, seen map[string]bool, citation string) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")

	for i, line := range lines {
		lineNum := block.firstLine + i
		if !block.addedLines[lineNum] && len(block.addedLines) > 0 {
			continue
		}

		if textButtonRe.MatchString(line) {
			// Scan the widget invocation (up to 30 lines)
			end := i + 30
			if end > len(lines) {
				end = len(lines)
			}
			chunk := strings.Join(lines[i:end], "\n")

			if shrinkWrapRe.MatchString(chunk) && minimumSizeZero.MatchString(chunk) {
				key := fmt.Sprintf("%s:%d", block.file, lineNum)
				if seen[key] {
					continue
				}
				seen[key] = true

				// Compute effective height
				vPad := 0.0
				if m := paddingVerticalRe.FindStringSubmatch(chunk); len(m) > 1 {
					vPad, _ = strconv.ParseFloat(m[1], 64)
				} else if m := paddingAllRe.FindStringSubmatch(chunk); len(m) > 1 {
					vPad, _ = strconv.ParseFloat(m[1], 64)
				}

				fSize := 14.0 // default text size
				if m := fontSizeRe.FindStringSubmatch(chunk); len(m) > 1 {
					fSize, _ = strconv.ParseFloat(m[1], 64)
				}

				computedHeight := fSize + (vPad * 2)
				if computedHeight < 48.0 {
					msg := fmt.Sprintf(
						"Interactive button explicitly shrinks hit target to %.0f dp (%.0f dp text + %.0f dp vertical padding) via shrinkWrap, below the 48 dp accessibility minimum",
						computedHeight, fSize, vPad*2,
					)
					remediation := "Remove tapTargetSize: MaterialTapTargetSize.shrinkWrap or set minimumSize to at least const Size(48, 48)."
					if citation != "" {
						remediation += " Adheres to " + citation + "."
					}

					finding := Finding{
						Rule:        "touch-target-size",
						Severity:    "medium",
						Category:    "quality",
						File:        block.file,
						Line:        lineNum,
						Message:     msg,
						Remediation: remediation,
						Confidence:  "High",
						Explanation: &model.FindingExplanation{
							RuleRationale:   "Interactive UI targets must be at least 48x48 dp to ensure accessible and accurate tapping.",
							EvidenceSummary: fmt.Sprintf("tapTargetSize shrinkWrap with minimumSize.zero reduces height to %.0f dp.", computedHeight),
							EvidenceKind:    "symbolic-geometry",
							EvidenceSteps: []model.ExplainedStep{
								{
									StepNumber: 1,
									Kind:       "source",
									Location:   fmt.Sprintf("%s:%d", block.file, lineNum),
									Statement:  "TextButton configured with tapTargetSize shrinkWrap and minimumSize.zero",
								},
								{
									StepNumber: 2,
									Kind:       "state",
									Statement:  fmt.Sprintf("Child font size = %.1f dp, vertical padding = %.1f dp", fSize, vPad),
								},
								{
									StepNumber: 3,
									Kind:       "sink",
									Statement:  fmt.Sprintf("Computed hit target height is %.1f dp (< 48 dp floor)", computedHeight),
								},
							},
						},
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

func (r TouchTargetRule) checkInteractiveWrappers(block diffSourceBlock, seen map[string]bool, citation string) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")

	for i, line := range lines {
		lineNum := block.firstLine + i
		if !block.addedLines[lineNum] && len(block.addedLines) > 0 {
			continue
		}

		m := inkWellRe.FindStringSubmatch(line)
		if len(m) == 0 {
			continue
		}
		widgetName := m[1]

		// Inspect enclosing / child widget context up to 45 lines
		end := i + 45
		if end > len(lines) {
			end = len(lines)
		}
		chunk := strings.Join(lines[i:end], "\n")

		// If this chunk or the surrounding lines already enforce >= 48dp, it is safe
		if minConstraint48Re.MatchString(chunk) {
			continue
		}

		// Also check 5 lines prior for a wrapping SizedBox(height: >=48) or ConstrainedBox
		priorStart := i - 5
		if priorStart < 0 {
			priorStart = 0
		}
		priorChunk := strings.Join(lines[priorStart:i], "\n")
		if minConstraint48Re.MatchString(priorChunk) {
			continue
		}

		evalChunk := chunk
		// If child references a variable (e.g. child: content), resolve definition from prior lines
		if cv := childVariableRe.FindStringSubmatch(chunk); len(cv) > 1 {
			varName := cv[1]
			varDefRe := regexp.MustCompile(fmt.Sprintf(`\b(?:final\s+)?%s\s*=`, regexp.QuoteMeta(varName)))
			pStart := i - 45
			if pStart < 0 {
				pStart = 0
			}
			for p := i - 1; p >= pStart; p-- {
				if varDefRe.MatchString(lines[p]) {
					defChunk := strings.Join(lines[p:i], "\n")
					evalChunk = defChunk + "\n" + chunk
					break
				}
			}
		}

		// Look for child padding
		vPad := -1.0
		if pm := paddingVerticalRe.FindStringSubmatch(evalChunk); len(pm) > 1 {
			vPad, _ = strconv.ParseFloat(pm[1], 64)
		} else if pm := paddingAllRe.FindStringSubmatch(evalChunk); len(pm) > 1 {
			vPad, _ = strconv.ParseFloat(pm[1], 64)
		} else if pm := paddingSymmetricV.FindStringSubmatch(evalChunk); len(pm) > 1 {
			vPad, _ = strconv.ParseFloat(pm[1], 64)
		}

		// Look for child height
		childHeight := -1.0
		childKind := ""
		if cm := containerHeightRe.FindStringSubmatch(evalChunk); len(cm) > 1 {
			childHeight, _ = strconv.ParseFloat(cm[1], 64)
			childKind = fmt.Sprintf("Container/SizedBox (height: %.0f dp)", childHeight)
		} else if im := iconSizeRe.FindStringSubmatch(evalChunk); len(im) > 1 {
			childHeight, _ = strconv.ParseFloat(im[1], 64)
			childKind = fmt.Sprintf("Icon (size: %.0f dp)", childHeight)
		} else if anyIconRe.MatchString(evalChunk) {
			childHeight = 24.0 // Flutter default icon size
			childKind = "Icon (default size: 24 dp)"
		}

		// If we found both padding and child height, calculate layout geometry
		if vPad >= 0 && childHeight > 0 {
			computedHeight := childHeight + (vPad * 2)
			if computedHeight < 48.0 {
				key := fmt.Sprintf("%s:%d", block.file, lineNum)
				if seen[key] {
					continue
				}
				seen[key] = true

				msg := fmt.Sprintf(
					"%s touch target has computed height of %.0f dp (%s + %.0f dp vertical padding), below the 48 dp accessibility minimum",
					widgetName, computedHeight, childKind, vPad*2,
				)
				remediation := fmt.Sprintf(
					"Wrap the %s content in a SizedBox(height: 48) or ConstrainedBox(constraints: BoxConstraints(minHeight: 48, minWidth: 48)).",
					widgetName,
				)
				if citation != "" {
					remediation += " Adheres to " + citation + "."
				}

				finding := Finding{
					Rule:        "touch-target-size",
					Severity:    "medium",
					Category:    "quality",
					File:        block.file,
					Line:        lineNum,
					Message:     msg,
					Remediation: remediation,
					Confidence:  "High",
					Explanation: &model.FindingExplanation{
						RuleRationale:   "WCAG 2.5.5 and mobile platform guidelines require interactive touch targets to be at least 48x48 dp to prevent missed taps.",
						EvidenceSummary: fmt.Sprintf("Calculated touch target height is %.0f dp (< 48 dp floor).", computedHeight),
						EvidenceKind:    "symbolic-geometry",
						EvidenceSteps: []model.ExplainedStep{
							{
								StepNumber: 1,
								Kind:       "source",
								Location:   fmt.Sprintf("%s:%d", block.file, lineNum),
								Statement:  fmt.Sprintf("Interactive widget %s wraps child without explicit minHeight constraint", widgetName),
							},
							{
								StepNumber: 2,
								Kind:       "state",
								Statement:  fmt.Sprintf("Inner component %s with vertical padding = %.1f dp", childKind, vPad),
							},
							{
								StepNumber: 3,
								Kind:       "sink",
								Statement:  fmt.Sprintf("Computed hit area bounding box height is %.1f dp (missing %.1f dp)", computedHeight, 48.0-computedHeight),
							},
						},
					},
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// findDesignSystemTouchTargetCitation inspects the repo's design system docs
// (e.g. design_system/*.md) for explicit touch target rules to cite.
func (r TouchTargetRule) findDesignSystemTouchTargetCitation() string {
	if r.RepositoryRoot == "" {
		return ""
	}

	candidates := []string{
		"design_system",
		"docs/design",
		"design-system",
	}

	targetRe := regexp.MustCompile(`(?i)(?:touch target|target size|minimum.*48|48\s*[×x]\s*48)`)

	for _, dirName := range candidates {
		dir := filepath.Join(r.RepositoryRoot, dirName)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".md") {
				docPath := filepath.Join(dir, entry.Name())
				data, err := os.ReadFile(docPath)
				if err != nil {
					continue
				}
				lines := strings.Split(string(data), "\n")
				for idx, l := range lines {
					if targetRe.MatchString(l) {
						rel, err := filepath.Rel(r.RepositoryRoot, docPath)
						if err != nil {
							rel = docPath
						}
						return fmt.Sprintf("%s:%d", filepath.ToSlash(rel), idx+1)
					}
				}
			}
		}
	}
	return ""
}
