package review

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

// HotPathRule is a deterministic performance static analyzer that detects
// expensive object allocations (RegExp recompilation, in-place sorting)
// inside hot paths such as Flutter build() methods, React render functions,
// and loops, preventing UI frame drops and unnecessary GC pressure.
type HotPathRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (HotPathRule) Name() string {
	return "hot-path-allocation"
}

func (r HotPathRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	// build() or render method signatures
	buildMethodRe = regexp.MustCompile(
		`\b(?:Widget\s+build\s*\(|render\s*\(\s*\)\s*\{|function\s+[A-Z]\w*\s*\([^)]*\)\s*\{)`,
	)

	// RegExp compilation inside code
	regExpInstRe = regexp.MustCompile(
		`\b(?:(?:new\s+)?RegExp\s*\(|re\.compile\s*\(|regexp\.(?:MustCompile|Compile)\s*\()`,
	)

	// In-place sort on collections
	inPlaceSortRe = regexp.MustCompile(
		`\.\s*sort\s*\(`,
	)
)

func (r HotPathRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		for _, block := range blocks {
			findings = append(findings, r.checkBlock(block, seen)...)
		}
	}

	return findings
}

func (r HotPathRule) checkBlock(block diffSourceBlock, seen map[string]bool) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")

	inBuildMethod := false
	methodDepth := 0

	for i, line := range lines {
		lineNum := block.firstLine + i

		// Track entering/exiting build methods
		if buildMethodRe.MatchString(line) {
			inBuildMethod = true
			methodDepth = 0
		}

		if inBuildMethod {
			for _, ch := range line {
				if ch == '{' {
					methodDepth++
				} else if ch == '}' {
					methodDepth--
					if methodDepth <= 0 {
						inBuildMethod = false
						break
					}
				}
			}
		}

		// Only inspect added lines
		if !block.addedLines[lineNum] && len(block.addedLines) > 0 {
			continue
		}

		// Check 1: RegExp inside build method
		if inBuildMethod && regExpInstRe.MatchString(line) {
			// Skip if line declares static or const
			if !strings.Contains(line, "static ") && !strings.Contains(line, "const ") {
				key := fmt.Sprintf("%s:%d:regexp", block.file, lineNum)
				if !seen[key] {
					seen[key] = true
					finding := Finding{
						Rule:        "hot-path-allocation",
						Severity:    "medium",
						Category:    "quality",
						File:        block.file,
						Line:        lineNum,
						Message:     "RegExp instantiated inside build() method; re-compiling pattern on every frame causes jank and GC pressure",
						Remediation: "Promote to a 'static final RegExp' field at class or file level to compile the regex once.",
						Confidence:  "High",
						Explanation: &model.FindingExplanation{
							RuleRationale:   "Regular expression compilation constructs an NFA/DFA automaton; compiling inside render loops drops 60fps frames.",
							EvidenceSummary: "RegExp allocation detected inside build() method body.",
							EvidenceKind:    "hot-path",
							EvidenceSteps: []model.ExplainedStep{
								{
									StepNumber: 1,
									Kind:       "source",
									Location:   fmt.Sprintf("%s:%d", block.file, lineNum),
									Statement:  "RegExp constructor invoked on every UI build pass",
								},
								{
									StepNumber: 2,
									Kind:       "sink",
									Statement:  "Repeated automaton construction and memory allocation in hot render path",
								},
							},
						},
					}
					findings = append(findings, finding)
				}
			}
		}

		// Check 2: In-place sorting inside build method
		if inBuildMethod && inPlaceSortRe.MatchString(line) {
			key := fmt.Sprintf("%s:%d:sort", block.file, lineNum)
			if !seen[key] {
				seen[key] = true
				finding := Finding{
					Rule:        "hot-path-allocation",
					Severity:    "medium",
					Category:    "quality",
					File:        block.file,
					Line:        lineNum,
					Message:     "Collection sorted inside build() method; running sorting algorithms on every frame causes UI stutter",
					Remediation: "Sort data when loading into State or memoize with a provider/useMemo instead of sorting during build.",
					Confidence:  "High",
					Explanation: &model.FindingExplanation{
						RuleRationale:   "O(N log N) sorting algorithms in render loops consume CPU budget needed for 60/120fps display refresh.",
						EvidenceSummary: "Collection .sort() called in build().",
						EvidenceKind:    "hot-path",
					},
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}
