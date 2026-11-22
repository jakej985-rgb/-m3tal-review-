package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// SimulationPermissionsRule detects UI components that advise users to modify
// host operating system hardware permissions (e.g. adding users to the `dialout`
// group or running sudo usermod) when the feature or screen is operating in
// simulation-only mode.
type SimulationPermissionsRule struct {
	ruleRuntime
}

func (SimulationPermissionsRule) Name() string { return "simulation-hardware-permissions" }

var (
	uiSourceFileRe = regexp.MustCompile(`\.(?:dart|tsx|jsx|vue|swift|kt)$`)

	// simulationContextRe detects indicators that the screen or component is a simulation
	simulationContextRe = regexp.MustCompile(`(?i)(?:simulation|virtual\s*simulation|virtual\s*hardware\s*bridge|hardware\s*companion\s*\(simulation\))`)

	// hostPermissionRe detects commands or instructions to modify host OS permissions
	hostPermissionRe = regexp.MustCompile(`(?i)(?:sudo\s+usermod\s+-[a-zA-Z]*G\s+dialout|sudo\s+adduser\s+\S+\s+dialout|chmod\s+[0-7]+\s+/dev/tty|dialout\s+group)`)
)

func (r SimulationPermissionsRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r SimulationPermissionsRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !uiSourceFileRe.MatchString(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		if !simulationContextRe.MatchString(scanText) {
			continue
		}

		lines := strings.Split(scanText, "\n")
		for i, line := range lines {
			lineNum := startLine + i
			if !block.addedLines[lineNum] && r.workingTree == false {
				continue
			}

			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
				continue
			}

			if hostPermissionRe.MatchString(line) {
				key := block.file + ":" + strconv.Itoa(lineNum)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, Finding{
						Rule:        "simulation-hardware-permissions",
						Severity:    "low",
						File:        block.file,
						Line:        lineNum,
						Message:     "UI advises host-level hardware permission configuration (dialout/usermod) in a simulation-only context",
						Remediation: "Remove host permission modification commands from simulation screens to avoid misleading users.",
					})
				}
			}
		}
	}

	return findings
}
