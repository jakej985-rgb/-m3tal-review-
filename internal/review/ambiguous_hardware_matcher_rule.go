package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// AmbiguousHardwareMatcherRule detects device matchers that return the first matching
// board when multiple distinct hardware targets share generic USB-to-UART bridge
// identifiers (such as CH340 0x1A86:0x7523 or CP2102 0x10C4:0xEA60). This causes
// 3.3V devices (e.g. ESP32) to inherit 5.0V board profiles and incorrect default baud rates.
type AmbiguousHardwareMatcherRule struct {
	ruleRuntime
}

func (AmbiguousHardwareMatcherRule) Name() string { return "ambiguous-hardware-matcher" }

var (
	hardwareRegistryFileRe = regexp.MustCompile(`(?i)(?:board|device|hardware|registry).*\.(?:dart|ts|js|go|py|kt|java)$`)

	// genericBridgeVidPidRe detects definitions of shared USB-to-UART bridge chips
	genericBridgeVidPidRe = regexp.MustCompile(`(?i)(?:0x1a86[,\s]+0x7523|0x10c4[,\s]+0xea60|0x0403[,\s]+0x6001|CH340|CP2102|FT232R)`)

	// firstMatchUsbLoopRe detects loops returning the first matching board by VID/PID
	firstMatchUsbLoopRe = regexp.MustCompile(`(?i)for\s*\(\s*(?:final|var|\w+)\s+\w+\s+in\s+\w+\s*\)\s*\{[\s\S]{0,150}?(?:vendorId|supportedVidsPids|vid)[\s\S]{0,150}?return\s+\w+;\s*}`)

	// ambiguityCheckRe detects whether the method handles ambiguous multi-matches
	ambiguityCheckRe = regexp.MustCompile(`(?i)(?:matches\.length\s*>\s*1|candidates\.length\s*>\s*1|return\s+unknownUsbSerial)`)
)

func (r AmbiguousHardwareMatcherRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r AmbiguousHardwareMatcherRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !hardwareRegistryFileRe.MatchString(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		// Only inspect files containing shared USB-to-UART bridges
		if !genericBridgeVidPidRe.MatchString(scanText) {
			continue
		}

		// If the file already handles ambiguous multi-match, skip
		if ambiguityCheckRe.MatchString(scanText) {
			continue
		}

		if loc := firstMatchUsbLoopRe.FindStringIndex(scanText); loc != nil {
			lineNum := startLine + strings.Count(scanText[:loc[0]], "\n")
			if block.addedLines[lineNum] || r.workingTree || len(block.addedLines) > 0 {
				key := block.file + ":" + strconv.Itoa(lineNum)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, Finding{
						Rule:        "ambiguous-hardware-matcher",
						Severity:    "medium",
						File:        block.file,
						Line:        lineNum,
						Message:     "USB board matcher returns the first match for shared USB bridge VID/PIDs without ambiguity handling",
						Remediation: "Treat shared USB-to-UART identifiers (e.g. CH340, CP2102) as ambiguous and fall back to a conservative unknown profile or require explicit board selection.",
					})
				}
			}
		}
	}

	return findings
}
