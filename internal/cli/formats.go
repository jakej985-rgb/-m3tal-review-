package cli

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"sort"
	"strings"
	"time"

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
		ID           string                   `json:"id,omitempty"`
		Rule         string                   `json:"rule"`
		Rules        []string                 `json:"rules,omitempty"`
		Analyzers    []string                 `json:"analyzers,omitempty"`
		Severity     string                   `json:"severity"`
		RawSeverity  string                   `json:"raw_severity,omitempty"`
		Confidence   string                   `json:"confidence,omitempty"`
		AdvisoryID   string                   `json:"advisory_id,omitempty"`
		AdvisoryIDs  []string                 `json:"advisory_ids,omitempty"`
		File         string                   `json:"file"`
		Line         int                      `json:"line"`
		Message      string                   `json:"message"`
		Remediation  string                   `json:"remediation,omitempty"`
		Category     string                   `json:"category,omitempty"`
		Signature    string                   `json:"signature,omitempty"`
		Snippet      string                   `json:"snippet,omitempty"`
		Evidence     []review.FindingEvidence `json:"evidence,omitempty"`
		Reachability string                   `json:"reachability,omitempty"`
		Metadata     map[string]string        `json:"metadata,omitempty"`
	}
	items := make([]item, 0, len(findings))
	for _, f := range findings {
		items = append(items, item{
			ID:           f.ID,
			Rule:         f.Rule,
			Rules:        f.Rules,
			Analyzers:    f.Analyzers,
			Severity:     f.Severity,
			RawSeverity:  f.RawSeverity,
			Confidence:   f.Confidence,
			AdvisoryID:   f.AdvisoryID,
			AdvisoryIDs:  f.AdvisoryIDs,
			File:         f.File,
			Line:         f.Line,
			Message:      f.Message,
			Remediation:  f.Remediation,
			Category:     f.Category,
			Signature:    f.Signature,
			Snippet:      f.Snippet,
			Evidence:     f.Evidence,
			Reachability: f.Reachability,
			Metadata:     f.Metadata,
		})
	}
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// formatFindingsJSONL emits findings as newline-delimited JSON for streaming report ingestion.
func formatFindingsJSONL(findings []review.Finding) (string, error) {
	var b strings.Builder
	if err := writeFindingsJSONL(&b, findings); err != nil {
		return "", err
	}
	return b.String(), nil
}

// writeFindingsJSONL streams findings to an io.Writer as newline-delimited JSON.
func writeFindingsJSONL(w io.Writer, findings []review.Finding) error {
	type item struct {
		ID           string                   `json:"id,omitempty"`
		Rule         string                   `json:"rule"`
		Rules        []string                 `json:"rules,omitempty"`
		Analyzers    []string                 `json:"analyzers,omitempty"`
		Severity     string                   `json:"severity"`
		RawSeverity  string                   `json:"raw_severity,omitempty"`
		Confidence   string                   `json:"confidence,omitempty"`
		AdvisoryID   string                   `json:"advisory_id,omitempty"`
		AdvisoryIDs  []string                 `json:"advisory_ids,omitempty"`
		File         string                   `json:"file"`
		Line         int                      `json:"line"`
		Message      string                   `json:"message"`
		Remediation  string                   `json:"remediation,omitempty"`
		Category     string                   `json:"category,omitempty"`
		Signature    string                   `json:"signature,omitempty"`
		Snippet      string                   `json:"snippet,omitempty"`
		Evidence     []review.FindingEvidence `json:"evidence,omitempty"`
		Reachability string                   `json:"reachability,omitempty"`
		Metadata     map[string]string        `json:"metadata,omitempty"`
	}
	for _, f := range findings {
		it := item{
			ID:           f.ID,
			Rule:         f.Rule,
			Rules:        f.Rules,
			Analyzers:    f.Analyzers,
			Severity:     f.Severity,
			RawSeverity:  f.RawSeverity,
			Confidence:   f.Confidence,
			AdvisoryID:   f.AdvisoryID,
			AdvisoryIDs:  f.AdvisoryIDs,
			File:         f.File,
			Line:         f.Line,
			Message:      f.Message,
			Remediation:  f.Remediation,
			Category:     f.Category,
			Signature:    f.Signature,
			Snippet:      f.Snippet,
			Evidence:     f.Evidence,
			Reachability: f.Reachability,
			Metadata:     f.Metadata,
		}
		data, err := json.Marshal(it)
		if err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
		if _, err := w.Write([]byte("\n")); err != nil {
			return err
		}
	}
	return nil
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

// formatFindingsHTML generates an interactive HTML report from a list of findings.
func formatFindingsHTML(findings []review.Finding) (string, error) {
	report := review.Report{
		Scope:     "staged",
		Timestamp: time.Now().UTC(),
		Findings:  findings,
	}
	passed := true
	for _, f := range findings {
		if f.Severity != "info" {
			passed = false
			break
		}
	}
	report.Passed = passed
	if passed {
		report.Summary = "Review passed. No findings."
	} else {
		report.Summary = "Review failed. Findings require attention."
	}
	return formatReportHTML(report)
}

// formatReportHTML generates an interactive, self-contained HTML report with embedded styles,
// finding filtering by severity, rule, and file, search box, and collapsible details with snippets.
func formatReportHTML(report review.Report) (string, error) {
	ruleSet := make(map[string]bool)
	fileSet := make(map[string]bool)
	sevCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

	for _, f := range report.Findings {
		if f.Rule != "" {
			ruleSet[f.Rule] = true
		}
		for _, r := range f.Rules {
			if r != "" {
				ruleSet[r] = true
			}
		}
		if f.File != "" {
			fileSet[f.File] = true
		}
		sev := strings.ToLower(f.Severity)
		sevCounts[sev]++
	}

	var sortedRules []string
	for r := range ruleSet {
		sortedRules = append(sortedRules, r)
	}
	sort.Strings(sortedRules)

	var sortedFiles []string
	for fl := range fileSet {
		sortedFiles = append(sortedFiles, fl)
	}
	sort.Strings(sortedFiles)

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>m3tal-review Report</title>
<style>
:root {
  --bg-body: #0d1117;
  --bg-card: #161b22;
  --bg-hover: #1c2128;
  --bg-code: #0a0c10;
  --border: #30363d;
  --text-main: #c9d1d9;
  --text-muted: #8b949e;
  --text-bright: #f0f6fc;
  --accent: #58a6ff;
  --pass: #238636;
  --pass-bg: #1f3825;
  --fail: #da3633;
  --fail-bg: #3d1d24;
  --sev-critical: #f85149;
  --sev-critical-bg: #3d1418;
  --sev-high: #ff7b72;
  --sev-high-bg: #3c1e1e;
  --sev-medium: #d29922;
  --sev-medium-bg: #3b2e16;
  --sev-low: #58a6ff;
  --sev-low-bg: #15293d;
  --sev-info: #8b949e;
  --sev-info-bg: #21262d;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background-color: var(--bg-body);
  color: var(--text-main);
  line-height: 1.5;
  padding: 24px;
}
.container { max-width: 1200px; margin: 0 auto; }
.report-header {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 24px;
  margin-bottom: 20px;
}
.header-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 12px;
}
.title-group { display: flex; align-items: center; gap: 12px; }
.title-group h1 { font-size: 22px; font-weight: 700; color: var(--text-bright); }
.status-badge {
  padding: 4px 12px;
  border-radius: 20px;
  font-size: 13px;
  font-weight: 700;
  text-transform: uppercase;
}
.status-badge.passed { background: var(--pass-bg); color: #3fb950; border: 1px solid var(--pass); }
.status-badge.failed { background: var(--fail-bg); color: #f85149; border: 1px solid var(--fail); }
.report-summary-text { font-size: 15px; color: var(--text-bright); margin-bottom: 16px; }
.metadata-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
  font-size: 13px;
  color: var(--text-muted);
}
.metadata-item strong { display: block; font-size: 11px; text-transform: uppercase; margin-bottom: 2px; color: var(--text-main); }
.metadata-item span, .metadata-item code { color: var(--text-bright); word-break: break-all; }
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}
.stat-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px;
  text-align: center;
  cursor: pointer;
  transition: transform 0.15s, border-color 0.15s;
}
.stat-card:hover { transform: translateY(-2px); border-color: var(--accent); }
.stat-card.active { border-color: var(--accent); background: var(--bg-hover); box-shadow: 0 0 0 1px var(--accent); }
.stat-val { font-size: 26px; font-weight: 700; color: var(--text-bright); }
.stat-label { font-size: 11px; text-transform: uppercase; color: var(--text-muted); margin-top: 4px; }
.stat-critical .stat-val { color: var(--sev-critical); }
.stat-high .stat-val { color: var(--sev-high); }
.stat-medium .stat-val { color: var(--sev-medium); }
.stat-low .stat-val { color: var(--sev-low); }
.stat-info .stat-val { color: var(--sev-info); }
.toolbar {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 20px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.toolbar-row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.search-wrapper { flex: 1; min-width: 250px; }
.search-input {
  width: 100%;
  padding: 8px 12px;
  background: var(--bg-body);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text-bright);
  font-size: 14px;
}
.search-input:focus { outline: none; border-color: var(--accent); }
.filter-select {
  padding: 8px 12px;
  background: var(--bg-body);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text-bright);
  font-size: 13px;
  min-width: 130px;
}
.btn {
  padding: 8px 14px;
  background: #21262d;
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text-bright);
  font-size: 13px;
  cursor: pointer;
}
.btn:hover { background: #30363d; }
.counter-text { font-size: 13px; color: var(--text-muted); margin-left: auto; }
.findings-container { display: flex; flex-direction: column; gap: 12px; }
.finding-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}
.finding-card:hover { border-color: #58a6ff66; }
.finding-summary {
  padding: 14px 18px;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 12px;
  user-select: none;
  list-style: none;
}
.finding-summary::-webkit-details-marker { display: none; }
.finding-summary:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
.finding-summary-left { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
.badge {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.badge-sev-critical { background: var(--sev-critical-bg); color: var(--sev-critical); border: 1px solid var(--sev-critical); }
.badge-sev-high { background: var(--sev-high-bg); color: var(--sev-high); border: 1px solid var(--sev-high); }
.badge-sev-medium { background: var(--sev-medium-bg); color: var(--sev-medium); border: 1px solid var(--sev-medium); }
.badge-sev-low { background: var(--sev-low-bg); color: var(--sev-low); border: 1px solid var(--sev-low); }
.badge-sev-info { background: var(--sev-info-bg); color: var(--sev-info); border: 1px solid var(--sev-info); }
.badge-rule { background: #21262d; color: var(--text-bright); border: 1px solid var(--border); font-family: monospace; }
.finding-loc { font-family: monospace; font-size: 13px; color: var(--accent); }
.finding-summary-title { flex: 1; font-size: 14px; color: var(--text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.chevron { color: var(--text-muted); font-size: 12px; transition: transform 0.2s; }
.finding-card[open] .chevron { transform: rotate(180deg); }
.finding-body {
  padding: 16px 18px;
  border-top: 1px solid var(--border);
  background: #10141b;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.finding-meta-row { display: flex; flex-wrap: wrap; gap: 16px; font-size: 12px; color: var(--text-muted); }
.finding-meta-row strong { color: var(--text-main); }
.finding-meta-row code { color: var(--text-bright); }
.finding-desc { font-size: 14px; color: var(--text-bright); }
.remediation-box {
  background: #1c2636;
  border-left: 4px solid var(--accent);
  padding: 10px 14px;
  border-radius: 0 6px 6px 0;
  font-size: 13px;
  color: #d1e4ff;
}
.remediation-title { font-weight: 700; margin-right: 6px; }
.snippet-box {
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg-code);
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: 12px;
  overflow-x: auto;
  padding: 12px;
  white-space: pre;
  line-height: 1.45;
  color: #e6edf3;
}
.snippet-table { border-collapse: collapse; width: 100%; font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; font-size: 12px; line-height: 1.45; }
.snippet-line.snippet-added { background-color: rgba(46, 160, 67, 0.15); }
.snippet-line.snippet-deleted { background-color: rgba(248, 81, 73, 0.15); }
.snippet-line.snippet-finding { background-color: rgba(210, 153, 34, 0.2); font-weight: 600; }
.snippet-line td { padding: 1px 6px; }
.snippet-line .marker { width: 16px; color: var(--accent); text-align: center; }
.snippet-line .line-num { width: 40px; color: var(--text-muted); text-align: right; user-select: none; }
.snippet-line .diff-sign { width: 16px; text-align: center; font-weight: bold; }
.snippet-line.snippet-added .diff-sign { color: #3fb950; }
.snippet-line.snippet-deleted .diff-sign { color: #f85149; }
.snippet-line .line-code { white-space: pre; }
.empty-state {
  background: var(--bg-card);
  border: 1px dashed var(--border);
  border-radius: 8px;
  padding: 40px;
  text-align: center;
  color: var(--text-muted);
  font-size: 15px;
}
.no-results {
  display: none;
  background: var(--bg-card);
  border: 1px dashed var(--border);
  border-radius: 8px;
  padding: 30px;
  text-align: center;
  color: var(--text-muted);
}
</style>
</head>
<body>
<div class="container">
`)

	// Report Header
	b.WriteString(`  <header class="report-header">` + "\n")
	b.WriteString(`    <div class="header-top">` + "\n")
	b.WriteString(`      <div class="title-group">` + "\n")
	b.WriteString(`        <h1>m3tal-review Report</h1>` + "\n")
	statusClass := "passed"
	statusText := "PASSED"
	if !report.Passed {
		statusClass = "failed"
		statusText = "FAILED"
	}
	fmt.Fprintf(&b, `        <span class="status-badge %s">%s</span>`+"\n", statusClass, statusText)
	b.WriteString(`      </div>` + "\n")
	if report.ToolVersion != "" {
		fmt.Fprintf(&b, `      <div class="tool-version">Version %s</div>`+"\n", html.EscapeString(report.ToolVersion))
	}
	b.WriteString(`    </div>` + "\n")

	if report.Summary != "" {
		fmt.Fprintf(&b, `    <div class="report-summary-text">%s</div>`+"\n", html.EscapeString(report.Summary))
	}

	b.WriteString(`    <div class="metadata-grid">` + "\n")
	if report.RunID != "" {
		fmt.Fprintf(&b, `      <div class="metadata-item"><strong>Run ID</strong><code>%s</code></div>`+"\n", html.EscapeString(report.RunID))
	}
	if !report.Timestamp.IsZero() {
		fmt.Fprintf(&b, `      <div class="metadata-item"><strong>Timestamp</strong><span>%s</span></div>`+"\n", report.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	if report.Repository != "" {
		fmt.Fprintf(&b, `      <div class="metadata-item"><strong>Repository</strong><span>%s</span></div>`+"\n", html.EscapeString(report.Repository))
	}
	if report.Branch != "" {
		fmt.Fprintf(&b, `      <div class="metadata-item"><strong>Branch</strong><span>%s</span></div>`+"\n", html.EscapeString(report.Branch))
	}
	if report.CommitSHA != "" {
		fmt.Fprintf(&b, `      <div class="metadata-item"><strong>Commit</strong><code>%s</code></div>`+"\n", html.EscapeString(report.CommitSHA))
	}
	if report.Scope != "" {
		fmt.Fprintf(&b, `      <div class="metadata-item"><strong>Scope</strong><span>%s</span></div>`+"\n", html.EscapeString(report.Scope))
	}
	b.WriteString(`    </div>` + "\n")
	b.WriteString(`  </header>` + "\n")

	// Stat cards
	b.WriteString(`  <section class="stats-grid">` + "\n")
	fmt.Fprintf(&b, `    <div class="stat-card" data-sev="" onclick="filterBySeverity('')"><div class="stat-val">%d</div><div class="stat-label">Total Findings</div></div>`+"\n", len(report.Findings))
	fmt.Fprintf(&b, `    <div class="stat-card stat-critical" data-sev="critical" onclick="filterBySeverity('critical')"><div class="stat-val">%d</div><div class="stat-label">Critical</div></div>`+"\n", sevCounts["critical"])
	fmt.Fprintf(&b, `    <div class="stat-card stat-high" data-sev="high" onclick="filterBySeverity('high')"><div class="stat-val">%d</div><div class="stat-label">High</div></div>`+"\n", sevCounts["high"])
	fmt.Fprintf(&b, `    <div class="stat-card stat-medium" data-sev="medium" onclick="filterBySeverity('medium')"><div class="stat-val">%d</div><div class="stat-label">Medium</div></div>`+"\n", sevCounts["medium"])
	fmt.Fprintf(&b, `    <div class="stat-card stat-low" data-sev="low" onclick="filterBySeverity('low')"><div class="stat-val">%d</div><div class="stat-label">Low</div></div>`+"\n", sevCounts["low"])
	fmt.Fprintf(&b, `    <div class="stat-card stat-info" data-sev="info" onclick="filterBySeverity('info')"><div class="stat-val">%d</div><div class="stat-label">Info</div></div>`+"\n", sevCounts["info"])
	b.WriteString(`  </section>` + "\n")

	// Controls toolbar
	b.WriteString(`  <div class="toolbar">` + "\n")
	b.WriteString(`    <div class="toolbar-row">` + "\n")
	b.WriteString(`      <div class="search-wrapper">` + "\n")
	b.WriteString(`        <input type="search" id="search-box" class="search-input" placeholder="Search findings (rule, file, message, code)...">` + "\n")
	b.WriteString(`      </div>` + "\n")
	b.WriteString(`      <select id="filter-severity" class="filter-select">` + "\n")
	b.WriteString(`        <option value="">All Severities</option>` + "\n")
	b.WriteString(`        <option value="critical">Critical</option>` + "\n")
	b.WriteString(`        <option value="high">High</option>` + "\n")
	b.WriteString(`        <option value="medium">Medium</option>` + "\n")
	b.WriteString(`        <option value="low">Low</option>` + "\n")
	b.WriteString(`        <option value="info">Info</option>` + "\n")
	b.WriteString(`      </select>` + "\n")

	// Rule select
	fmt.Fprintf(&b, `      <select id="filter-rule" class="filter-select"><option value="">All Rules (%d)</option>`, len(sortedRules))
	for _, r := range sortedRules {
		fmt.Fprintf(&b, `<option value="%s">%s</option>`, html.EscapeString(r), html.EscapeString(r))
	}
	b.WriteString(`</select>` + "\n")

	// File select
	fmt.Fprintf(&b, `      <select id="filter-file" class="filter-select"><option value="">All Files (%d)</option>`, len(sortedFiles))
	for _, fl := range sortedFiles {
		fmt.Fprintf(&b, `<option value="%s">%s</option>`, html.EscapeString(fl), html.EscapeString(fl))
	}
	b.WriteString(`</select>` + "\n")

	b.WriteString(`    </div>` + "\n")
	b.WriteString(`    <div class="toolbar-row">` + "\n")
	b.WriteString(`      <button type="button" class="btn" onclick="expandAllFindings(true)">Expand All</button>` + "\n")
	b.WriteString(`      <button type="button" class="btn" onclick="expandAllFindings(false)">Collapse All</button>` + "\n")
	b.WriteString(`      <button type="button" class="btn" onclick="resetFilters()">Reset Filters</button>` + "\n")
	fmt.Fprintf(&b, `      <span id="filter-count" class="counter-text">Showing %d of %d findings</span>`+"\n", len(report.Findings), len(report.Findings))
	b.WriteString(`    </div>` + "\n")
	b.WriteString(`  </div>` + "\n")

	// Findings list
	if len(report.Findings) == 0 {
		b.WriteString(`  <div class="empty-state">No findings detected. Review passed!</div>` + "\n")
	} else {
		b.WriteString(`  <div class="findings-container">` + "\n")
		for _, f := range report.Findings {
			sev := strings.ToLower(f.Severity)
			loc := html.EscapeString(f.File)
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", loc, f.Line)
			}
			allRules := []string{f.Rule}
			for _, r := range f.Rules {
				if r != "" && r != f.Rule {
					allRules = append(allRules, r)
				}
			}
			dataRules := strings.Join(allRules, ",")
			fmt.Fprintf(&b, `    <details class="finding-card" data-severity="%s" data-rule="%s" data-rules="%s" data-file="%s">`+"\n",
				html.EscapeString(sev), html.EscapeString(f.Rule), html.EscapeString(dataRules), html.EscapeString(f.File))
			b.WriteString(`      <summary class="finding-summary">` + "\n")
			b.WriteString(`        <div class="finding-summary-left">` + "\n")
			fmt.Fprintf(&b, `          <span class="badge badge-sev-%s">%s</span>`+"\n", html.EscapeString(sev), html.EscapeString(f.Severity))
			fmt.Fprintf(&b, `          <span class="badge badge-rule">%s</span>`+"\n", html.EscapeString(f.Rule))
			if loc != "" {
				fmt.Fprintf(&b, `          <span class="finding-loc">%s</span>`+"\n", loc)
			}
			b.WriteString(`        </div>` + "\n")
			fmt.Fprintf(&b, `        <div class="finding-summary-title">%s</div>`+"\n", html.EscapeString(f.Message))
			b.WriteString(`        <span class="chevron">&#9662;</span>` + "\n")
			b.WriteString(`      </summary>` + "\n")

			b.WriteString(`      <div class="finding-body">` + "\n")
			b.WriteString(`        <div class="finding-meta-row">` + "\n")
			if f.Category != "" {
				fmt.Fprintf(&b, `          <span><strong>Category:</strong> %s</span>`+"\n", html.EscapeString(f.Category))
			}
			if f.Confidence != "" {
				fmt.Fprintf(&b, `          <span><strong>Confidence:</strong> %s</span>`+"\n", html.EscapeString(f.Confidence))
			}
			if f.ID != "" {
				fmt.Fprintf(&b, `          <span><strong>ID:</strong> <code>%s</code></span>`+"\n", html.EscapeString(f.ID))
			}
			if f.File != "" && f.Line > 0 {
				fmt.Fprintf(&b, `          <span><strong>Location:</strong> %s:%d</span>`+"\n", html.EscapeString(f.File), f.Line)
			}
			if f.Signature != "" {
				fmt.Fprintf(&b, `          <span><strong>Signature:</strong> <code>%s</code></span>`+"\n", html.EscapeString(f.Signature))
			}
			if len(f.Analyzers) > 0 {
				fmt.Fprintf(&b, `          <span><strong>Analyzers:</strong> %s</span>`+"\n", html.EscapeString(strings.Join(f.Analyzers, ", ")))
			}
			b.WriteString(`        </div>` + "\n")

			fmt.Fprintf(&b, `        <div class="finding-desc"><p>%s</p></div>`+"\n", html.EscapeString(f.Message))

			if f.Remediation != "" {
				fmt.Fprintf(&b, `        <div class="remediation-box"><span class="remediation-title">&#128161; Remediation:</span><span>%s</span></div>`+"\n",
					html.EscapeString(f.Remediation))
			}

			if f.Snippet != "" {
				fmt.Fprintf(&b, `        <div class="snippet-box"><code>%s</code></div>`+"\n", html.EscapeString(f.Snippet))
			}

			b.WriteString(`      </div>` + "\n")
			b.WriteString(`    </details>` + "\n")
		}
		b.WriteString(`  </div>` + "\n")
		b.WriteString(`  <div id="no-results" class="no-results">No findings match the active filters.</div>` + "\n")
	}

	// Interactive JavaScript
	b.WriteString(`</div>
<script>
(function() {
  const searchBox = document.getElementById('search-box');
  const sevFilter = document.getElementById('filter-severity');
  const ruleFilter = document.getElementById('filter-rule');
  const fileFilter = document.getElementById('filter-file');
  const countEl = document.getElementById('filter-count');
  const cards = Array.from(document.querySelectorAll('.finding-card'));
  const noResults = document.getElementById('no-results');
  const statCards = Array.from(document.querySelectorAll('.stat-card'));

  function updateActiveStatCard(activeSev) {
    statCards.forEach(sc => {
      const scSev = (sc.getAttribute('data-sev') || '').toLowerCase();
      if ((!activeSev && scSev === '') || (activeSev && scSev === activeSev)) {
        sc.classList.add('active');
      } else {
        sc.classList.remove('active');
      }
    });
  }

  function applyFilters() {
    const rawQuery = searchBox ? searchBox.value.trim().toLowerCase() : '';
    const queryWords = rawQuery ? rawQuery.split(/\s+/).filter(Boolean) : [];
    const sev = sevFilter ? sevFilter.value.toLowerCase() : '';
    const rule = ruleFilter ? ruleFilter.value : '';
    const file = fileFilter ? fileFilter.value : '';

    updateActiveStatCard(sev);

    let visible = 0;
    cards.forEach(card => {
      const cardSev = (card.getAttribute('data-severity') || '').toLowerCase();
      const cardRule = card.getAttribute('data-rule') || '';
      const cardRules = (card.getAttribute('data-rules') || cardRule).split(',');
      const cardFile = card.getAttribute('data-file') || '';
      const cardText = card.textContent.toLowerCase();

      const matchSev = !sev || cardSev === sev;
      const matchRule = !rule || cardRule === rule || cardRules.includes(rule);
      const matchFile = !file || cardFile === file;
      const matchQuery = queryWords.length === 0 || queryWords.every(w => cardText.includes(w));

      if (matchSev && matchRule && matchFile && matchQuery) {
        card.style.display = '';
        visible++;
      } else {
        card.style.display = 'none';
      }
    });

    if (countEl) {
      countEl.textContent = 'Showing ' + visible + ' of ' + cards.length + ' finding' + (cards.length === 1 ? '' : 's');
    }
    if (noResults) {
      noResults.style.display = (visible === 0 && cards.length > 0) ? 'block' : 'none';
    }
  }

  if (searchBox) {
    searchBox.addEventListener('input', applyFilters);
    searchBox.addEventListener('search', applyFilters);
  }
  if (sevFilter) sevFilter.addEventListener('change', applyFilters);
  if (ruleFilter) ruleFilter.addEventListener('change', applyFilters);
  if (fileFilter) fileFilter.addEventListener('change', applyFilters);

  window.expandAllFindings = function(open) {
    if (!open) {
      cards.forEach(c => c.open = false);
    } else {
      cards.forEach(c => { if (c.style.display !== 'none') c.open = true; });
    }
  };

  window.resetFilters = function() {
    if (searchBox) searchBox.value = '';
    if (sevFilter) sevFilter.value = '';
    if (ruleFilter) ruleFilter.value = '';
    if (fileFilter) fileFilter.value = '';
    applyFilters();
  };

  window.filterBySeverity = function(sev) {
    if (sevFilter) {
      const cur = sevFilter.value.toLowerCase();
      const target = (sev || '').toLowerCase();
      sevFilter.value = (cur === target) ? '' : target;
      applyFilters();
    }
  };

  applyFilters();
})();
</script>
</body>
</html>
`)
	return b.String(), nil
}
