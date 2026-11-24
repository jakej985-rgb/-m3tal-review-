package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// CourseCompletionGatingRule detects course completion checks that rely on
// in-memory loaded sibling lesson lists (e.g. siblings.every) rather than verifying
// the authoritative course definition (course.lessonIds). When assets are loaded in
// fallback or truncated mode, evaluating completion against loaded siblings awards
// premature course credit without all required course lessons being completed.
type CourseCompletionGatingRule struct {
	ruleRuntime
}

func (CourseCompletionGatingRule) Name() string {
	return "course-completion-authoritative-gating"
}

var (
	courseCompletionFileRe = regexp.MustCompile(`(?i)(?:lesson|course|curriculum|progress|learn).*\.dart$`)

	// siblingCompletionCheckRe detects completing a course based on loaded sibling lessons
	siblingCompletionCheckRe = regexp.MustCompile(`\b(?:siblings|loadedLessons|courseLessons)\s*\.\s*every\s*\(`)

	// courseCreditGrantRe detects granting course completion credit or status
	courseCreditGrantRe = regexp.MustCompile(`(?i)(?:\b(?:markCourseComplete\w*|completeCourse\w*|awardCredit\w*|grantCredit\w*|markCompleted\w*|setCourseCompleted\w*)\b|\b(?:courseCompleted|isCourseCompleted|isCourseComplete)\s*=\s*(?:true|1)\b)`)

	// authoritativeLessonIdsEveryRe checks for authoritative progress evaluation on all required course lesson IDs
	authoritativeLessonIdsEveryRe = regexp.MustCompile(`\b\w+\.lessonIds\s*\.\s*every\s*\(`)

	// authoritativeEarlyExitRe detects early exit on non-authoritative completion
	authoritativeEarlyExitRe = regexp.MustCompile(`(?s)if\s*\([^;{}]*!\s*\w+\.lessonIds\s*\.\s*every\s*\([^)]*\)[^;{}]*\)\s*(?:return\b|throw\b|\{[^}]*(?:return\b|throw\b))`)
)

func hasPrecedingAuthoritativeGuard(lines []string, currentIdx int) bool {
	startIdx := currentIdx - 50
	if startIdx < 0 {
		startIdx = 0
	}
	slice := strings.Join(lines[startIdx:currentIdx], "\n")
	if authoritativeEarlyExitRe.MatchString(slice) {
		return true
	}

	braceDepth := 0
	for k := currentIdx - 1; k >= startIdx; k-- {
		l := lines[k]
		for idx := len(l) - 1; idx >= 0; idx-- {
			if l[idx] == '}' {
				braceDepth++
			} else if l[idx] == '{' {
				if braceDepth > 0 {
					braceDepth--
				} else {
					if strings.Contains(l, "if") && authoritativeLessonIdsEveryRe.MatchString(l) && !strings.Contains(l, "!") {
						return true
					}
				}
			}
		}
	}
	return false
}

func (r CourseCompletionGatingRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r CourseCompletionGatingRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !courseCompletionFileRe.MatchString(block.file) || isTestFile(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		if !siblingCompletionCheckRe.MatchString(scanText) {
			continue
		}

		lines := strings.Split(scanText, "\n")
		for i, line := range lines {
			if siblingCompletionCheckRe.MatchString(line) {
				// Inspect the surrounding completion path (up to 30 lines)
				end := i + 30
				if end > len(lines) {
					end = len(lines)
				}
				contextSlice := strings.Join(lines[i:end], "\n")

				// Must grant course credit or mark completion
				if !courseCreditGrantRe.MatchString(contextSlice) {
					continue
				}

				// If this completion path evaluates authoritative course.lessonIds.every, it's safe
				if authoritativeLessonIdsEveryRe.MatchString(contextSlice) {
					continue
				}

				// If a preceding check in the same function guards with an authoritative check, it's safe
				if hasPrecedingAuthoritativeGuard(lines, i) {
					continue
				}

				lineNum := startLine + i
				if len(block.addedLines) > 0 {
					touchesAdded := false
					firstAdded := -1
					for l := startLine + i; l < startLine+end; l++ {
						if block.addedLines[l] {
							touchesAdded = true
							if firstAdded == -1 {
								firstAdded = l
							}
						}
					}
					if !touchesAdded {
						continue
					}
					if !block.addedLines[lineNum] && firstAdded != -1 {
						lineNum = firstAdded
					}
				}

				key := block.file + ":" + strconv.Itoa(lineNum)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, Finding{
						Rule:        "course-completion-authoritative-gating",
						Severity:    "high",
						File:        block.file,
						Line:        lineNum,
						Message:     "Course completion relies on loaded sibling lessons rather than authoritative course.lessonIds",
						Remediation: "Verify course completion against the authoritative course definition (course.lessonIds.isNotEmpty && course.lessonIds.every(...)) to prevent fallback placeholders from granting real course credit.",
					})
				}
			}
		}
	}

	return findings
}
