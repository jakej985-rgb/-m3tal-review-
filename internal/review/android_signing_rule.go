package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// AndroidSigningRule flags dangerous release signing configurations in Gradle
// build scripts (build.gradle / build.gradle.kts):
//  1. Conditionally assigning debug signingConfig to the release buildType.
//  2. Gating release signing requirements on gradle.startParameter.taskNames,
//     which aggregate tasks (assemble, build) bypass.
type AndroidSigningRule struct {
	ruleRuntime
}

func (AndroidSigningRule) Name() string { return "android-signing-bypass" }

var (
	gradleFileRe = regexp.MustCompile(`(?:^|/)(?:build\.gradle(?:\.kts)?|app/build\.gradle(?:\.kts)?)$`)

	// taskNamesCheckRe detects gating signing checks on CLI task names.
	taskNamesCheckRe = regexp.MustCompile(`(?:gradle\.startParameter\.taskNames|startParameter\.taskNames)\.any\b|taskNames\.(?:any|contains)\b`)

	// releaseDebugFallbackRe detects assigning debug signingConfig in a release block or fallback.
	releaseDebugFallbackRe = regexp.MustCompile(`signingConfigs\.(?:getByName\("debug"\)|debug\b)|signingConfig\s*=\s*(?:signingConfigs\.)?debug\b`)

	// bundleOrPackageSigningCheckRe checks for release packaging tasks validation.
	bundleOrPackageSigningCheckRe = regexp.MustCompile(`(?i)(?:bundleRelease|packageRelease|validateSigningRelease|allTasks\.any\s*\{[^}]*Release)`)
)

func (r AndroidSigningRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r AndroidSigningRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !gradleFileRe.MatchString(block.file) {
			continue
		}

		lines := strings.Split(block.text, "\n")
		inReleaseBlock := false
		releaseIndent := -1

		for i, line := range lines {
			lineNum := block.firstLine + i
			indent := len(line) - len(strings.TrimLeft(line, " \t"))
			trimmed := strings.TrimSpace(line)

			if strings.HasPrefix(trimmed, "release {") || strings.HasPrefix(trimmed, "getByName(\"release\") {") || trimmed == "release" {
				inReleaseBlock = true
				releaseIndent = indent
			} else if inReleaseBlock && indent <= releaseIndent && trimmed == "}" {
				inReleaseBlock = false
				releaseIndent = -1
			}

			if !block.addedLines[lineNum] {
				continue
			}

			if taskNamesCheckRe.MatchString(line) {
				key := block.file + ":" + strconv.Itoa(lineNum)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, Finding{
						Rule:        "android-signing-bypass",
						Severity:    "high",
						File:        block.file,
						Line:        lineNum,
						Message:     "Release signing requirements gated on CLI startParameter task names; aggregate build tasks (assemble) bypass this check",
						Remediation: "Enforce release keystore validation on the release variant task execution graph rather than checking startParameter task names.",
					})
				}
			}

			if inReleaseBlock && releaseDebugFallbackRe.MatchString(line) {
				key := block.file + ":" + strconv.Itoa(lineNum)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, Finding{
						Rule:        "android-signing-bypass",
						Severity:    "high",
						File:        block.file,
						Line:        lineNum,
						Message:     "Release buildType assigns or falls back to debug signingConfig",
						Remediation: "Bind release signing directly to the release signingConfig; fail closed if release credentials are not configured.",
					})
				}
			} else if inReleaseBlock && strings.Contains(line, "signingConfig") && !releaseDebugFallbackRe.MatchString(line) {
				fullScanText := block.text
				if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
					fullScanText = string(fullData)
				}
				if !bundleOrPackageSigningCheckRe.MatchString(fullScanText) {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:        "android-signing-bypass",
							Severity:    "high",
							File:        block.file,
							Line:        lineNum,
							Message:     "Release signing lacks execution-time validation on release packaging tasks (bundleRelease/packageRelease); missing keystores allow unsigned release bundles to build",
							Remediation: "Add execution-time signing validation requiring the release keystore as a dependency of bundleRelease and packageRelease tasks.",
						})
					}
				}
			}
		}
	}

	return findings
}
