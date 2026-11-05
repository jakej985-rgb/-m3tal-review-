package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// sarifReport is a minimal SARIF 2.1.0 document for CI ingestion.
type sarifReport struct {
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
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
}

type sarifResult struct {
	RuleID    string       `json:"ruleId"`
	Level     string       `json:"level"`
	Message   sarifMessage `json:"message"`
	Locations []sarifLoc   `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLoc struct {
	PhysicalLocation sarifPhys `json:"physicalLocation"`
}

type sarifPhys struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func sarifLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func formatFindingsSarif(findings []review.Finding) (string, error) {
	ruleIDs := make(map[string]bool)
	var rules []sarifRule
	for _, f := range findings {
		if !ruleIDs[f.Rule] {
			ruleIDs[f.Rule] = true
			r := sarifRule{ID: f.Rule, Name: f.Rule}
			r.ShortDescription.Text = f.Message
			rules = append(rules, r)
		}
	}
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		result := sarifResult{
			RuleID:  f.Rule,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Message},
		}
		if f.File != "" {
			region := sarifRegion{}
			if f.Line > 0 {
				region.StartLine = f.Line
			}
			result.Locations = []sarifLoc{{PhysicalLocation: sarifPhys{
				ArtifactLocation: sarifArtifact{URI: f.File},
				Region:           region,
			}}}
		}
		results = append(results, result)
	}
	doc := sarifReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:    appName,
				Version: version,
				Rules:   rules,
			}},
			Results: results,
		}},
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// formatFindingsGitHub emits GitHub Actions workflow-command annotations.
func formatFindingsGitHub(findings []review.Finding) string {
	var b strings.Builder
	for _, f := range findings {
		level := "warning"
		switch f.Severity {
		case "critical", "high":
			level = "error"
		case "info":
			level = "notice"
		}
		location := f.File
		if f.Line > 0 {
			location = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		message := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(f.Message)
		title := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ",", "%2C", ":", "%3A").Replace(f.Rule)
		fmt.Fprintf(&b, "::%s file=%s,title=%s::%s (%s)\n", level, location, title, message, f.Severity)
	}
	return b.String()
}
