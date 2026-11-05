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

// formatFindingsJSON emits findings as a JSON array for tooling.
func formatFindingsJSON(findings []review.Finding) (string, error) {
	type item struct {
		ID          string `json:"id,omitempty"`
		Rule        string `json:"rule"`
		Severity    string `json:"severity"`
		File        string `json:"file"`
		Line        int    `json:"line"`
		Message     string `json:"message"`
		Remediation string `json:"remediation,omitempty"`
		Category    string `json:"category,omitempty"`
	}
	items := make([]item, 0, len(findings))
	for _, f := range findings {
		items = append(items, item{ID: f.ID, Rule: f.Rule, Severity: f.Severity, File: f.File, Line: f.Line, Message: f.Message, Remediation: f.Remediation, Category: f.Category})
	}
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// formatFindingsJUnit emits JUnit XML for CI test-report aggregation.
func formatFindingsJUnit(findings []review.Finding) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<testsuite name="m3tal-review" tests="`)
	b.WriteString(itoaLen(len(findings)))
	b.WriteString(`" failures="`)
	failures := 0
	for _, f := range findings {
		if f.Severity == "high" || f.Severity == "critical" {
			failures++
		}
	}
	b.WriteString(itoaLen(failures))
	b.WriteString(`">` + "\n")
	for _, f := range findings {
		name := xmlEscape(f.Rule + " " + f.Message)
		b.WriteString(`  <testcase classname="` + xmlEscape(f.File) + `" name="` + name + `">` + "\n")
		b.WriteString(`    <failure message="` + xmlEscape(f.Severity+": "+f.Message) + `"/>` + "\n")
		b.WriteString(`  </testcase>` + "\n")
	}
	b.WriteString(`</testsuite>` + "\n")
	return b.String()
}

// formatFindingsCodeClimate emits CodeClimate-compatible JSON issues.
func formatFindingsCodeClimate(findings []review.Finding) (string, error) {
	type issue struct {
		CheckName   string `json:"check_name"`
		Description string `json:"description"`
		Categories  string `json:"categories"`
		Location    struct {
			Path  string `json:"path"`
			Lines struct {
				Begin int `json:"begin"`
			} `json:"lines"`
		} `json:"location"`
		Severity string `json:"severity"`
	}
	issues := make([]issue, 0, len(findings))
	for _, f := range findings {
		var it issue
		it.CheckName = f.Rule
		it.Description = f.Message
		it.Categories = "Security"
		it.Location.Path = f.File
		it.Location.Lines.Begin = f.Line
		it.Severity = f.Severity
		issues = append(issues, it)
	}
	data, err := json.MarshalIndent(issues, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func itoaLen(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}
