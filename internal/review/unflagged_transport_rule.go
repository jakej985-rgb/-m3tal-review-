package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// UnflaggedTransportRule detects when physical or experimental hardware transports are
// instantiated unconditionally as the default application bridge without feature flags,
// environment toggles, or runtime preferences. When project architecture specifies
// virtual simulation as the default safe baseline, unconditionally activating physical
// USB transports exposes unverified experimental peripherals to production learners.
type UnflaggedTransportRule struct {
	ruleRuntime
}

func (UnflaggedTransportRule) Name() string { return "unflagged-experimental-transport" }

var (
	bridgeServiceFileRe = regexp.MustCompile(`(?i)(?:hardware_bridge_service|bridge_factory|hardware_provider).*\.(?:dart|ts|js)$`)

	// unflaggedCompositeBridgeRe detects returning CompositeHardwareBridge or PhysicalSerialBridge directly
	unflaggedCompositeBridgeRe = regexp.MustCompile(`(?i)createDefaultBridge\s*\([^)]*\)\s*\{[\s\S]{0,100}?return\s+(?:CompositeHardwareBridge|PhysicalSerialBridge)\s*\(\s*\);`)

	// featureFlagCheckRe detects checking feature flags or preferences
	featureFlagCheckRe = regexp.MustCompile(`(?i)(?:featureFlag|enablePhysical|allowPhysical|kReleaseMode|config\.isPhysicalEnabled)`)
)

func (r UnflaggedTransportRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r UnflaggedTransportRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !bridgeServiceFileRe.MatchString(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		if featureFlagCheckRe.MatchString(scanText) {
			continue
		}

		if loc := unflaggedCompositeBridgeRe.FindStringIndex(scanText); loc != nil {
			lineNum := startLine + strings.Count(scanText[:loc[0]], "\n")
			if block.addedLines[lineNum] || r.workingTree || len(block.addedLines) > 0 {
				key := block.file + ":" + strconv.Itoa(lineNum)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, Finding{
						Rule:        "unflagged-experimental-transport",
						Severity:    "medium",
						File:        block.file,
						Line:        lineNum,
						Message:     "Hardware bridge factory instantiates real physical USB transport unconditionally by default",
						Remediation: "Gate physical hardware transport instantiation behind a feature flag, runtime setting, or preserve virtual simulation as the default bridge.",
					})
				}
			}
		}
	}

	return findings
}
