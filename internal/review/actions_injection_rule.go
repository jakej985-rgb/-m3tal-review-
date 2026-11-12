package review

import (
	"regexp"
	"strconv"
	"strings"
)

// ActionsScriptInjectionRule flags ${{ github.event.* }} interpolations that
// land in executable workflow contexts — `run:` and `script:` (github-script)
// steps, including block-scalar bodies. Interpolations in structural YAML
// keys (ref:, with: inputs, if:, env:, names) are data, not shell, and are
// not flagged.
type ActionsScriptInjectionRule struct {
	ruleRuntime
}

func (ActionsScriptInjectionRule) Name() string { return "actions-script-injection" }

var (
	workflowFileRe = regexp.MustCompile(`(?:^|/)\.github/workflows/.*\.ya?ml$`)
	eventInterpRe  = regexp.MustCompile(`\$\{\{\s*github\.event\.[^}]+\}\}`)
	// execKeyRe matches `run:` or `script:` step keys at any indent, with an
	// optional leading `- ` list marker.
	execKeyRe = regexp.MustCompile(`^(\s*)(?:-\s*)?(run|script)\s*:`)
	// blockScalarRe matches YAML block scalar indicators (| or > with
	// optional chomping/indent modifiers) after the key.
	blockScalarRe = regexp.MustCompile(`^\s*[|>][+-]?\d*\s*$|^\s*[|>][+-]?[1-9]?\s`)
	// attackerContextRe marks event data an attacker can author (issue/PR/
	// comment bodies, head refs, commit messages): those stay high severity.
	// Dispatch inputs, event names, and SHAs require write access: medium.
	attackerContextRe = regexp.MustCompile(`github\.event\.(?:issue|comment|review|discussion|pull_request|head_commit|commits|pages)|github\.head_ref`)
)

func (r ActionsScriptInjectionRule) Check(diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	const message = "Event data interpolated into workflow; risk of script injection"
	const remediation = "Pass event data through environment variables instead of interpolating ${{ }} into run scripts."

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if !workflowFileRe.MatchString(block.file) {
			continue
		}
		lines := strings.Split(block.text, "\n")
		// execIndent tracks the indent of the currently open run:/script:
		// block-scalar key; -1 means no executable block is open.
		execIndent := -1
		for i, line := range lines {
			lineNum := block.firstLine + i
			trimmed := strings.TrimSpace(line)
			indent := len(line) - len(strings.TrimLeft(line, " \t"))

			if execKeyRe.MatchString(line) {
				// A run:/script: key opens an executable context: the rest of
				// this line (inline value) plus any block-scalar body.
				keyIndent := indent
				if m := execKeyRe.FindStringSubmatch(line); m != nil {
					// Indent of the key itself (spaces before '-' or key).
					keyIndent = len(m[1])
				}
				afterColon := line[strings.Index(line, ":")+1:]
				isBlock := blockScalarRe.MatchString(strings.TrimSpace(afterColon)) ||
					strings.TrimSpace(afterColon) == ""
				if isBlock {
					execIndent = keyIndent
				} else {
					execIndent = -1
				}
				// Inline values on the key line are executable too.
				if eventInterpRe.MatchString(line) && block.addedLines[lineNum] {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, r.finding(block.file, lineNum, line, message, remediation))
					}
				}
				continue
			}

			// Inside a block scalar: deeper-indented lines are script body.
			// Dedent to the key's level (or shallower) closes the block;
			// blank lines don't affect indentation state.
			if execIndent >= 0 {
				if trimmed == "" {
					// Blank line inside block: still potentially script.
					continue
				}
				if indent <= execIndent {
					execIndent = -1
				} else if eventInterpRe.MatchString(line) && block.addedLines[lineNum] {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, r.finding(block.file, lineNum, line, message, remediation))
					}
					continue
				}
			}
		}
	}
	return findings
}

func (r ActionsScriptInjectionRule) finding(file string, line int, text, message, remediation string) Finding {
	severity := "medium"
	if attackerContextRe.MatchString(text) {
		severity = "high"
	}
	return Finding{
		Rule:        "actions-script-injection",
		Severity:    severity,
		File:        file,
		Line:        line,
		Message:     message,
		Remediation: remediation,
	}
}
