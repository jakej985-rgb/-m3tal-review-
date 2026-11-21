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

// ResourceLeakRule is a deterministic lifecycle static analyzer that verifies
// disposable and cancelable resources (controllers, timers, streams, focus nodes)
// in StatefulWidget states are properly closed in dispose() to prevent memory
// leaks and dangling background timers.
type ResourceLeakRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (ResourceLeakRule) Name() string {
	return "resource-leak-disposable"
}

func (r ResourceLeakRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	// State class definition: class _MyWidgetState extends State<MyWidget>
	stateClassRe = regexp.MustCompile(
		`\bclass\s+(_[A-Z]\w*State)\s+extends\s+(?:Consumer)?State<`,
	)

	// Disposable field declarations in Flutter/Dart
	disposableFieldRe = regexp.MustCompile(
		`\b(?:final\s+|late\s+final\s+|late\s+)?(TextEditingController|AnimationController|ScrollController|TabController|PageController|FocusNode|Timer|StreamSubscription[<>\w]*)\??\s+(_[a-zA-Z0-9_]+)\s*(?:=|;)`,
	)

	// dispose() method declaration
	disposeMethodRe = regexp.MustCompile(
		`\bvoid\s+dispose\s*\(\s*\)\s*\{`,
	)
)

func (r ResourceLeakRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if !isUIFile(filePath) || isTestFile(filePath) {
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
			findings = append(findings, r.checkBlock(block, fileText, seen)...)
		}
	}

	return findings
}

type disposableFieldInfo struct {
	typeName  string
	fieldName string
	lineNum   int
}

func (r ResourceLeakRule) checkBlock(block diffSourceBlock, fileText string, seen map[string]bool) []Finding {
	var findings []Finding

	scanText := block.text
	if fileText != "" {
		scanText = fileText
	}

	// 1. Check if class is a State class
	if !stateClassRe.MatchString(scanText) {
		return nil
	}

	// 2. Extract dispose() method body if present
	disposeBody := ""
	hasDispose := false
	if dm := disposeMethodRe.FindStringIndex(scanText); len(dm) > 0 {
		hasDispose = true
		disposeStart := dm[0]
		disposeEnd := disposeStart + 400
		if disposeEnd > len(scanText) {
			disposeEnd = len(scanText)
		}
		disposeBody = scanText[disposeStart:disposeEnd]
	}

	// 3. Scan block for newly added or declared disposable fields
	lines := strings.Split(block.text, "\n")
	for i, line := range lines {
		lineNum := block.firstLine + i
		if !block.addedLines[lineNum] && len(block.addedLines) > 0 {
			continue
		}

		if m := disposableFieldRe.FindStringSubmatch(line); len(m) > 2 {
			typeName := m[1]
			fieldName := m[2]

			// Check if field is cleaned up in dispose()
			cleanedUp := false
			if hasDispose {
				cleanupPattern := regexp.MustCompile(
					fmt.Sprintf(`\b%s\??\.(?:dispose|cancel)\s*\(`, regexp.QuoteMeta(fieldName)),
				)
				if cleanupPattern.MatchString(disposeBody) {
					cleanedUp = true
				}
			}

			if !cleanedUp {
				key := fmt.Sprintf("%s:%d:%s", block.file, lineNum, fieldName)
				if seen[key] {
					continue
				}
				seen[key] = true

				methodToCall := "dispose"
				if strings.Contains(typeName, "Timer") || strings.Contains(typeName, "StreamSubscription") {
					methodToCall = "cancel"
				}

				msg := fmt.Sprintf(
					"Disposable resource '%s' (%s) allocated in State but not cleaned up in dispose(); causes memory leaks and dangling listeners",
					fieldName, typeName,
				)
				remediation := fmt.Sprintf(
					"Add '%s?.%s();' to the State class's dispose() method.",
					fieldName, methodToCall,
				)

				finding := Finding{
					Rule:        "resource-leak-disposable",
					Severity:    "high",
					Category:    "quality",
					File:        block.file,
					Line:        lineNum,
					Message:     msg,
					Remediation: remediation,
					Confidence:  "High",
					Explanation: &model.FindingExplanation{
						RuleRationale:   "StatefulWidget controllers and subscriptions must be released in dispose() to free native resources and prevent leaks.",
						EvidenceSummary: fmt.Sprintf("%s field %s is never released in dispose().", typeName, fieldName),
						EvidenceKind:    "lifecycle-cleanup",
						EvidenceSteps: []model.ExplainedStep{
							{
								StepNumber: 1,
								Kind:       "source",
								Location:   fmt.Sprintf("%s:%d", block.file, lineNum),
								Statement:  fmt.Sprintf("Allocated %s field %s", typeName, fieldName),
							},
							{
								StepNumber: 2,
								Kind:       "sink",
								Statement:  fmt.Sprintf("dispose() method fails to invoke %s.%s()", fieldName, methodToCall),
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
