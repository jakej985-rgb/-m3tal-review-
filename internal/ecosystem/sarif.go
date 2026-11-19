// Package ecosystem generates hardened SARIF v2.1.0 documents with codeFlows and fixes.
package ecosystem

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

type sarifDoc struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifText       `json:"shortDescription"`
	HelpURI          string          `json:"helpUri,omitempty"`
	DefaultConfig    sarifRuleConfig `json:"defaultConfiguration"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
	CodeFlows []sarifCodeFlow `json:"codeFlows,omitempty"`
	Fixes     []sarifFix      `json:"fixes,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifCodeFlow struct {
	ThreadFlows []sarifThreadFlow `json:"threadFlows"`
}

type sarifThreadFlow struct {
	Locations []sarifThreadFlowLocation `json:"locations"`
}

type sarifThreadFlowLocation struct {
	Location sarifLocation `json:"location"`
}

type sarifFix struct {
	Description     sarifText             `json:"description"`
	ArtifactChanges []sarifArtifactChange `json:"artifactChanges"`
}

type sarifArtifactChange struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Replacements     []sarifReplacement    `json:"replacements"`
}

type sarifReplacement struct {
	DeletedRegion   sarifRegion `json:"deletedRegion"`
	InsertedContent sarifText   `json:"insertedContent"`
}

func mapSarifLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// FormatFileURI encodes file paths safely for SARIF URI fields.
func FormatFileURI(filePath string) string {
	parts := strings.Split(filePath, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func buildSarifLocation(file string, line, col int) sarifLocation {
	return sarifLocation{
		PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: FormatFileURI(file)},
			Region: sarifRegion{
				StartLine:   line,
				StartColumn: col,
			},
		},
	}
}

func buildSarifRule(ruleName, msg, sev string) sarifRule {
	return sarifRule{
		ID:               ruleName,
		Name:             ruleName,
		ShortDescription: sarifText{Text: msg},
		HelpURI:          "https://github.com/jakej985-rgb/-m3tal-review-",
		DefaultConfig:    sarifRuleConfig{Level: mapSarifLevel(sev)},
	}
}

func buildSarifResult(f model.Finding, ruleName string) sarifResult {
	res := sarifResult{
		RuleID:  ruleName,
		Level:   mapSarifLevel(f.Severity),
		Message: sarifText{Text: f.Message},
	}

	if f.File != "" {
		res.Locations = []sarifLocation{buildSarifLocation(f.File, f.Line, 0)}
	}

	if f.Explanation != nil && len(f.Explanation.EvidenceSteps) > 0 {
		var threadLocs []sarifThreadFlowLocation
		for _, step := range f.Explanation.EvidenceSteps {
			threadLocs = append(threadLocs, sarifThreadFlowLocation{
				Location: buildSarifLocation(step.Location, 0, 0),
			})
		}
		res.CodeFlows = []sarifCodeFlow{{ThreadFlows: []sarifThreadFlow{{Locations: threadLocs}}}}
	}

	if f.Remediation != "" {
		res.Fixes = []sarifFix{{
			Description: sarifText{Text: f.Remediation},
			ArtifactChanges: []sarifArtifactChange{{
				ArtifactLocation: sarifArtifactLocation{URI: FormatFileURI(f.File)},
				Replacements: []sarifReplacement{{
					DeletedRegion:   sarifRegion{StartLine: f.Line},
					InsertedContent: sarifText{Text: f.Remediation},
				}},
			}},
		}}
	}

	return res
}

// GenerateSARIFReport converts model findings to a valid SARIF v2.1.0 JSON report.
func GenerateSARIFReport(findings []model.Finding, appVersion string) ([]byte, error) {
	ruleMap := make(map[string]sarifRule)
	var results []sarifResult

	for _, f := range findings {
		ruleName := f.Rule
		if ruleName == "" {
			ruleName = "unknown-rule"
		}
		if _, exists := ruleMap[ruleName]; !exists {
			ruleMap[ruleName] = buildSarifRule(ruleName, f.Message, f.Severity)
		}
		results = append(results, buildSarifResult(f, ruleName))
	}

	var rules []sarifRule
	for _, r := range ruleMap {
		rules = append(rules, r)
	}

	doc := sarifDoc{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "m3tal-review",
					Version:        appVersion,
					InformationURI: "https://github.com/jakej985-rgb/-m3tal-review-",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	return json.MarshalIndent(doc, "", "  ")
}
