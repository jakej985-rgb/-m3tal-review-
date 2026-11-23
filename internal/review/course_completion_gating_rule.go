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

	// authoritativeCheckRe checks for authoritative course.lessonIds verification
	authoritativeCheckRe = regexp.MustCompile(`\b\w+\.lessonIds\s*\.\s*(?:isNotEmpty|every)`)
)

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

		// If the file already verifies authoritative course.lessonIds, skip
		if authoritativeCheckRe.MatchString(scanText) {
			continue
		}

		lines := strings.Split(scanText, "\n")
		for i, line := range lines {
			lineNum := startLine + i
			if !block.addedLines[lineNum] && !r.workingTree && len(block.addedLines) == 0 {
				continue
			}

			if siblingCompletionCheckRe.MatchString(line) {
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
