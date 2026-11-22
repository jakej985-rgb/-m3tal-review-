package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// RouteGuardSchemaRule detects routing guards that evaluate stored entities using
// shallow key lookups (e.g. `(item as Map)['id'] == activeId`) instead of validating
// the entity against its domain model schema (e.g. `Model.fromJson`). If required fields
// are missing or malformed, the route guard allows entry but domain repositories reject
// the entity, leaving the application in a headless state without an active record.
type RouteGuardSchemaRule struct {
	ruleRuntime
}

func (RouteGuardSchemaRule) Name() string { return "route-guard-schema-mismatch" }

var (
	routeGuardFileRe = regexp.MustCompile(`(?i)(?:router|route|guard|navigation).*\.(?:dart|ts|js|go|py|kt)$`)

	// shallowMapLookupRe matches checking an entity ID via raw map casting instead of Model.fromJson
	shallowMapLookupRe = regexp.MustCompile(`(?i)(?:\((?:item|e|entry)\s*as\s*Map[<>\w,\s]*\)|(?:item|e|entry|map))\s*\[\s*['"]id['"]\s*\]\s*==\s*\w+`)

	// modelFromJsonRe matches model deserialization
	modelFromJsonRe = regexp.MustCompile(`(?i)\b\w+Model\.fromJson\b`)
)

func (r RouteGuardSchemaRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r RouteGuardSchemaRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !routeGuardFileRe.MatchString(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		// If the file already employs model deserialization in its guard logic, skip
		if modelFromJsonRe.MatchString(scanText) {
			continue
		}

		lines := strings.Split(scanText, "\n")
		for i, line := range lines {
			lineNum := startLine + i
			trimmed := strings.TrimSpace(line)

			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
				continue
			}

			if shallowMapLookupRe.MatchString(trimmed) {
				if block.addedLines[lineNum] || r.workingTree {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:        "route-guard-schema-mismatch",
							Severity:    "medium",
							File:        block.file,
							Line:        lineNum,
							Message:     "Route guard checks entity presence using raw map lookups without validating model schema integrity",
							Remediation: "Validate entity records using domain model deserialization (e.g. Model.fromJson) to ensure corrupted records do not bypass onboarding or auth gates.",
						})
					}
				}
			}
		}
	}

	return findings
}
