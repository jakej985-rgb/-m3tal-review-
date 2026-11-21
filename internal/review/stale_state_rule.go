package review

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

// StaleStateRule is a deterministic static analyzer that verifies lifecycle
// state invalidation contracts in reactive UI frameworks (Flutter didUpdateWidget
// and React componentDidUpdate/useEffect):
// 1. It flags when an entity ID change refreshes a resource but fails to reset
//    cursor/index state (preventing RangeError / index out of bounds crashes).
// 2. It flags tests that test a widget with didUpdateWidget but keep parameters
//    fixed, leaving update and cache invalidation branches unexercised.
type StaleStateRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (StaleStateRule) Name() string {
	return "stale-state-invalidation"
}

func (r StaleStateRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	// Flutter didUpdateWidget signature
	didUpdateWidgetRe = regexp.MustCompile(
		`\bvoid\s+didUpdateWidget\s*\(\s*(?:covariant\s+)?([A-Z]\w*)\s+([a-zA-Z]\w*)\s*\)`,
	)

	// Entity property check: oldWidget.id != widget.id or widget.id != oldWidget.id
	entityChangeRe = regexp.MustCompile(
		`\b(?:([a-zA-Z]\w*)\.([a-zA-Z0-9_]*[iI][dD]|[a-zA-Z0-9_]*[kK]ey)\s*!=\s*widget\.([a-zA-Z0-9_]+)|widget\.([a-zA-Z0-9_]+)\s*!=\s*([a-zA-Z]\w*)\.([a-zA-Z0-9_]*[iI][dD]|[a-zA-Z0-9_]*[kK]ey))\b`,
	)

	// State cursor / index variables: int _currentStepIndex, int _selectedIndex, etc.
	cursorFieldRe = regexp.MustCompile(
		`\bint\s+(_[a-zA-Z0-9]*(?:Index|Step|Page|Cursor|Position|Tab))\s*=`,
	)

	// Direct collection indexing: steps[_currentStepIndex], items[_selectedIndex]
	collectionIndexRe = regexp.MustCompile(
		`\[\s*(_[a-zA-Z0-9]*(?:Index|Step|Page|Cursor|Position|Tab))\s*\]`,
	)
)

func (r StaleStateRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if isTestFile(filePath) {
			// Check test files for untested didUpdateWidget contracts
			findings = append(findings, r.checkTestFile(fileDiff, seen)...)
			continue
		}

		if !isUIFile(filePath) {
			continue
		}

		fileText := ""
		if r.RepositoryRoot != "" {
			if data, err := os.ReadFile(filepath.Join(r.RepositoryRoot, filePath)); err == nil {
				fileText = string(data)
			}
		}
		if fileText == "" {
			if data, err := os.ReadFile(filePath); err == nil {
				fileText = string(data)
			}
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		for _, block := range blocks {
			findings = append(findings, r.checkUIBlock(block, fileText, seen)...)
		}
	}

	return findings
}

func (r StaleStateRule) checkUIBlock(block diffSourceBlock, fileText string, seen map[string]bool) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")

	scanText := block.text
	if fileText != "" {
		scanText = fileText
	}
	scanLines := strings.Split(scanText, "\n")

	// 1. Scan for cursor fields
	var cursorFields []string
	for _, l := range scanLines {
		if m := cursorFieldRe.FindStringSubmatch(l); len(m) > 1 {
			cursorFields = append(cursorFields, m[1])
		}
	}

	if len(cursorFields) == 0 {
		return nil
	}

	// Verify that at least one cursor field is actually indexed into a collection
	indexedCursors := make(map[string]bool)
	for _, l := range scanLines {
		for _, m := range collectionIndexRe.FindAllStringSubmatch(l, -1) {
			if len(m) > 1 {
				indexedCursors[m[1]] = true
			}
		}
	}

	// 2. Scan for didUpdateWidget
	for i, line := range lines {
		lineNum := block.firstLine + i
		if !block.addedLines[lineNum] && len(block.addedLines) > 0 {
			continue
		}

		if didUpdateWidgetRe.MatchString(line) {
			// Extract didUpdateWidget body (up to 35 lines)
			end := i + 35
			if end > len(lines) {
				end = len(lines)
			}
			chunk := strings.Join(lines[i:end], "\n")

			em := entityChangeRe.FindStringSubmatch(chunk)
			if len(em) == 0 {
				continue
			}

			propName := em[2]
			if propName == "" {
				propName = em[3]
			}
			if propName == "" {
				propName = em[4]
			}
			if propName == "" {
				propName = em[6]
			}
			if propName == "" {
				propName = "entity ID"
			}

			// Check which indexed cursors are NOT reset in this chunk
			for cursor := range indexedCursors {
				resetPattern := regexp.MustCompile(fmt.Sprintf(`\b%s\s*=\s*0\b`, regexp.QuoteMeta(cursor)))
				if !resetPattern.MatchString(chunk) {
					key := fmt.Sprintf("%s:%d:%s", block.file, lineNum, cursor)
					if seen[key] {
						continue
					}
					seen[key] = true

					msg := fmt.Sprintf(
						"didUpdateWidget updates resource on %s change but does not reset cursor %s; accessing collection[%s] will throw RangeError if new entity has fewer items",
						propName, cursor, cursor,
					)
					remediation := fmt.Sprintf(
						"Reset %s = 0 and clear any item-specific progress state in didUpdateWidget when %s changes.",
						cursor, propName,
					)

					finding := Finding{
						Rule:        "stale-state-invalidation",
						Severity:    "high",
						Category:    "quality",
						File:        block.file,
						Line:        lineNum,
						Message:     msg,
						Remediation: remediation,
						Confidence:  "High",
						Explanation: &model.FindingExplanation{
							RuleRationale:   "StatefulWidget cursors must be reset when underlying entity changes to avoid fatal out-of-bounds indexing.",
							EvidenceSummary: fmt.Sprintf("didUpdateWidget updates state on %s change without resetting %s.", propName, cursor),
							EvidenceKind:    "state-lifecycle",
							EvidenceSteps: []model.ExplainedStep{
								{
									StepNumber: 1,
									Kind:       "source",
									Location:   fmt.Sprintf("%s:%d", block.file, lineNum),
									Statement:  fmt.Sprintf("didUpdateWidget handles %s change", propName),
								},
								{
									StepNumber: 2,
									Kind:       "state",
									Statement:  fmt.Sprintf("Cursor %s retained from previous entity", cursor),
								},
								{
									StepNumber: 3,
									Kind:       "sink",
									Statement:  fmt.Sprintf("Subsequent build accesses collection[%s] risking RangeError on shorter entities", cursor),
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

func (r StaleStateRule) checkTestFile(fileDiff FileDiff, seen map[string]bool) []Finding {
	var findings []Finding
	blocks := fileDiffSourceBlocks(fileDiff)

	pumpWidgetRe := regexp.MustCompile(`\bawait\s+tester\.pumpWidget\s*\(`)
	testWidgetsRe := regexp.MustCompile(`\btestWidgets\s*\(\s*['"]([^'"]+)['"]`)
	screenParamRe := regexp.MustCompile(`\b([A-Z]\w*(?:Screen|View|Page))\s*\([^)]*([a-zA-Z0-9_]*[iI][dD]|[a-zA-Z0-9_]*[kK]ey)\s*:\s*['"]([^'"]+)['"]`)

	for _, block := range blocks {
		lines := strings.Split(block.text, "\n")
		for i, line := range lines {
			lineNum := block.firstLine + i
			if !block.addedLines[lineNum] && len(block.addedLines) > 0 {
				continue
			}

			if tm := testWidgetsRe.FindStringSubmatch(line); len(tm) > 1 {
				// Scan test body up to 60 lines
				end := i + 60
				if end > len(lines) {
					end = len(lines)
				}
				chunk := strings.Join(lines[i:end], "\n")

				pumps := pumpWidgetRe.FindAllStringIndex(chunk, -1)
				// If test only pumps widget once and has an explicit ID parameter
				if len(pumps) == 1 {
					if sm := screenParamRe.FindStringSubmatch(chunk); len(sm) > 3 {
						screenName := sm[1]
						paramName := sm[2]
						paramVal := sm[3]

						// Check if test name or comments mention testing cache, fetch efficiency, or reuse
						lowerChunk := strings.ToLower(chunk)
						if strings.Contains(lowerChunk, "fetch") || strings.Contains(lowerChunk, "cache") || strings.Contains(lowerChunk, "rebuild") {
							key := fmt.Sprintf("%s:%d", block.file, lineNum)
							if seen[key] {
								continue
							}
							seen[key] = true

							msg := fmt.Sprintf(
								"Test '%s' verifies cache/fetch for %s with static %s: '%s', but never pumps an updated %s; cache invalidation and didUpdateWidget branches are unexercised",
								tm[1], screenName, paramName, paramVal, paramName,
							)
							remediation := fmt.Sprintf(
								"Pump the widget a second time with a different %s (e.g. %s: '%s_alt') to test cache refresh and didUpdateWidget state reset.",
								paramName, paramName, paramVal,
							)

							finding := Finding{
								Rule:        "stale-state-invalidation",
								Severity:    "low",
								Category:    "quality",
								File:        block.file,
								Line:        lineNum,
								Message:     msg,
								Remediation: remediation,
								Confidence:  "High",
							}
							findings = append(findings, finding)
						}
					}
				}
			}
		}
	}

	return findings
}
