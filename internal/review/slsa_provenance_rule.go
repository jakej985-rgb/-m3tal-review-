package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// SLSAProvenanceRule flags malformed SLSA provenance generators.
// Specifically, in-toto statements declaring SLSA predicateType must enclose
// builder, recipe, and metadata inside a top-level `predicate: { ... }` object.
type SLSAProvenanceRule struct {
	ruleRuntime
}

func (SLSAProvenanceRule) Name() string { return "slsa-provenance-schema" }

var (
	provenanceFileRe = regexp.MustCompile(`(?:^|/)(?:.*provenance.*|.*slsa.*)\.(?:py|go|js|ts|json)$`)
	slsaPredicateRe  = regexp.MustCompile(`["']predicateType["']\s*:\s*["']https://slsa\.dev/provenance/`)
	topLevelBuilder  = regexp.MustCompile(`["']builder["']\s*:\s*\{`)
	predicateKeyRe   = regexp.MustCompile(`["']predicate["']\s*:\s*\{`)
)

func (r SLSAProvenanceRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r SLSAProvenanceRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !provenanceFileRe.MatchString(block.file) {
			continue
		}

		if !slsaPredicateRe.MatchString(block.text) {
			continue
		}

		// If the file creates an in-toto statement with builder at the top level
		// without a predicate wrapper:
		if topLevelBuilder.MatchString(block.text) && !predicateKeyRe.MatchString(block.text) {
			lines := strings.Split(block.text, "\n")
			for i, line := range lines {
				lineNum := block.firstLine + i
				if !block.addedLines[lineNum] {
					continue
				}

				if slsaPredicateRe.MatchString(line) || topLevelBuilder.MatchString(line) {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:        "slsa-provenance-schema",
							Severity:    "high",
							File:        block.file,
							Line:        lineNum,
							Message:     "SLSA provenance in-toto Statement declares predicateType but omits required top-level 'predicate' wrapper object",
							Remediation: "Enclose builder, recipe, and metadata objects inside a top-level 'predicate: { ... }' field per SLSA provenance specification.",
						})
					}
				}
			}
		}
	}

	return findings
}
