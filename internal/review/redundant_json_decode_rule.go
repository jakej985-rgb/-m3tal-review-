package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// RedundantJsonDecodeRule detects routing guards or data transformers that decode the
// same raw JSON string multiple times in the same decision path (e.g. validating
// decodability via tryDecodeList and then immediately re-decoding in a membership check).
// Decoding should be performed once with the parsed model list reused.
type RedundantJsonDecodeRule struct {
	ruleRuntime
}

func (RedundantJsonDecodeRule) Name() string {
	return "redundant-json-decode"
}

var (
	redundantJsonFileRe = regexp.MustCompile(
		`(?i)(?:router|route|guard|navigation|datasource|loader).*\.(?:dart|ts|js|go|py|kt)$`,
	)
	redundantJsonExcludeRe = regexp.MustCompile(
		`(?i)(?:_test\.[a-z0-9]+|(?:^|/)(?:tests?|testdata|fixtures?)/)`,
	)

	// redundantDecodePatternRe matches calling decoders multiple times on the same input in a block
	repeatedDecoderCallRe = regexp.MustCompile(
		`(?i)(?:tryDecodeList|jsonDecode|json\.decode|deserializeList)\s*\(\s*(\w+)\s*\)`,
	)
)

func (r RedundantJsonDecodeRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r RedundantJsonDecodeRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !redundantJsonFileRe.MatchString(block.file) || redundantJsonExcludeRe.MatchString(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		lines := strings.Split(scanText, "\n")
		// Check for multiple decode helper calls on the same raw variable within ~20 lines
		for i, line := range lines {
			lineNum := startLine + i
			trimmed := strings.TrimSpace(line)

			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
				continue
			}

			// Pattern 1: A function calling two separate helper functions that each decode the same parameter
			if strings.Contains(trimmed, "_decodesProfiles(") &&
				strings.Contains(lines[min(i+1, len(lines)-1)], "_containsLoadableProfile(") {
				if block.addedLines[lineNum] || r.workingTree {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:     "redundant-json-decode",
							Severity: "medium",
							File:     block.file,
							Line:     lineNum,
							Message:  "Redundant JSON decoding: payload is decoded for validation and decoded again for lookup",
							Remediation: "Decode the JSON payload once and inspect the parsed collection directly " +
								"rather than re-parsing in subsequent helpers.",
						})
					}
				}
			}

			// Pattern 2: Consecutive tryDecodeList / jsonDecode calls on the same variable without assignment
			matches := repeatedDecoderCallRe.FindAllStringSubmatch(trimmed, -1)
			if len(matches) > 1 && matches[0][1] == matches[1][1] {
				if block.addedLines[lineNum] || r.workingTree {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:     "redundant-json-decode",
							Severity: "medium",
							File:     block.file,
							Line:     lineNum,
							Message:  "Redundant JSON decoding: same variable decoded multiple times in expression",
							Remediation: "Cache the decoded JSON object in a local variable before inspecting properties.",
						})
					}
				}
			}
		}
	}

	return findings
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
