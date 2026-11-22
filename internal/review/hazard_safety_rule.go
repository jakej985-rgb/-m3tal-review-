package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// HazardSafetyRule flags components or curriculum definitions containing severe
// physical hazards (laser, retinal injury, mains AC, fire/burn hazards) that are
// misclassified as "caution"/"safe" or have requiresParentUnlock=false.
type HazardSafetyRule struct {
	ruleRuntime
}

func (HazardSafetyRule) Name() string { return "hazard-safety-classification" }

var (
	componentFileRe = regexp.MustCompile(`(?:^|/)(?:components?/.*|curriculum/.*|.*comp_.*)\.(?:json|ya?ml)$`)

	// severeHazardTerms matches high-risk physical hazards.
	severeHazardTerms = regexp.MustCompile(`(?i)\b(?:laser|retinal injury|mains ac|high-voltage|combustible gas)\b`)

	// misclassifiedSafety matches safety level not being restrictedAdultSupervision or requiresParentUnlock being false.
	misclassifiedLevelRe   = regexp.MustCompile(`["']level["']\s*:\s*["'](?:caution|safe)["']`)
	bypassedParentUnlockRe = regexp.MustCompile(`["']requiresParentUnlock["']\s*:\s*false\b`)
)

func (r HazardSafetyRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r HazardSafetyRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !componentFileRe.MatchString(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		// Only check files with severe physical hazard keywords.
		if !severeHazardTerms.MatchString(scanText) {
			continue
		}

		lines := strings.Split(scanText, "\n")
		for i, line := range lines {
			lineNum := startLine + i

			// Check for misclassified level or false requiresParentUnlock
			if misclassifiedLevelRe.MatchString(line) {
				key := block.file + ":" + strconv.Itoa(lineNum) + ":level"
				if !seen[key] {
					seen[key] = true
					findings = append(findings, Finding{
						Rule:        "hazard-safety-classification",
						Severity:    "high",
						File:        block.file,
						Line:        lineNum,
						Message:     "Component contains high-risk physical hazard indicators (laser/retinal/mains AC) but safety level is set to caution/safe",
						Remediation: "Set `level: \"restrictedAdultSupervision\"` and `requiresParentUnlock: true` for any component posing physical safety risks.",
					})
				}
			}

			if bypassedParentUnlockRe.MatchString(line) {
				key := block.file + ":" + strconv.Itoa(lineNum) + ":unlock"
				if !seen[key] {
					seen[key] = true
					findings = append(findings, Finding{
						Rule:        "hazard-safety-classification",
						Severity:    "high",
						File:        block.file,
						Line:        lineNum,
						Message:     "Component contains high-risk physical hazard indicators but requiresParentUnlock is set to false",
						Remediation: "Require parent authorization (`requiresParentUnlock: true`) for components with laser, retinal, burn, or electrical hazards.",
					})
				}
			}
		}
	}

	return findings
}
