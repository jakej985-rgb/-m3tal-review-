package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestFormatFindingsJSONL(t *testing.T) {
	findings := []review.Finding{
		{
			ID:          "find-001",
			Rule:        "hardcoded-credential",
			Severity:    "high",
			File:        "config.go",
			Line:        15,
			Message:     "Found hardcoded password",
			Remediation: "Use env var",
			Category:    "security",
			Snippet:     "[config.go:15] (go)\n > 15 | + apiKey := \"123\"\n",
		},
		{
			ID:          "find-002",
			Rule:        "todo-marker",
			Severity:    "low",
			File:        "utils.go",
			Line:        42,
			Message:     "TODO leftover",
			Remediation: "Remove or track in backlog",
			Category:    "review",
		},
	}

	out, err := formatFindingsJSONL(findings)
	if err != nil {
		t.Fatalf("formatFindingsJSONL failed: %v", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(out))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan jsonl lines: %v", err)
	}

	if len(lines) != 2 {
		t.Fatalf("expected 2 JSONL lines, got %d", len(lines))
	}

	type jsonlItem struct {
		ID          string `json:"id"`
		Rule        string `json:"rule"`
		Severity    string `json:"severity"`
		File        string `json:"file"`
		Line        int    `json:"line"`
		Message     string `json:"message"`
		Remediation string `json:"remediation"`
		Category    string `json:"category"`
		Snippet     string `json:"snippet"`
	}

	var item1 jsonlItem
	if err := json.Unmarshal([]byte(lines[0]), &item1); err != nil {
		t.Fatalf("unmarshal line 1: %v", err)
	}
	if item1.ID != "find-001" || item1.Rule != "hardcoded-credential" || item1.Severity != "high" {
		t.Errorf("unexpected item1 fields: %+v", item1)
	}
	if item1.Snippet == "" || !strings.Contains(item1.Snippet, "apiKey :=") {
		t.Errorf("expected snippet in item1: %s", item1.Snippet)
	}

	var item2 jsonlItem
	if err := json.Unmarshal([]byte(lines[1]), &item2); err != nil {
		t.Fatalf("unmarshal line 2: %v", err)
	}
	if item2.ID != "find-002" || item2.Line != 42 {
		t.Errorf("unexpected item2 fields: %+v", item2)
	}
}

func TestFormatFindingsJSONLEmpty(t *testing.T) {
	out, err := formatFindingsJSONL(nil)
	if err != nil {
		t.Fatalf("formatFindingsJSONL(nil) error: %v", err)
	}
	if out != "" {
		t.Errorf("expected empty string for 0 findings, got %q", out)
	}
}

func TestWriteFindingsJSONLStreaming(t *testing.T) {
	findings := []review.Finding{
		{Rule: "r1", Severity: "medium", File: "a.py", Line: 5, Message: "m1"},
	}
	var buf bytes.Buffer
	if err := writeFindingsJSONL(&buf, findings); err != nil {
		t.Fatalf("writeFindingsJSONL error: %v", err)
	}
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Errorf("expected newline termination")
	}
}

func TestFormatReportHTML(t *testing.T) {
	report := review.Report{
		Scope:       "staged",
		Profile:     "security",
		RunID:       "run-abc-123",
		Timestamp:   time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC),
		Repository:  "test-repo",
		Branch:      "feature/auth",
		CommitSHA:   "0123456789abcdef",
		ToolVersion: "1.0.0",
		Passed:      false,
		Summary:     "Review failed. 2 finding(s) require attention.",
		Findings: []review.Finding{
			{
				ID:          "f1",
				Rule:        "hardcoded-credential",
				Severity:    "critical",
				File:        "auth.go",
				Line:        25,
				Message:     "AWS Access Key exposed: AKIAIOSFODNN7EXAMPLE",
				Remediation: "Remove credential from source",
				Category:    "security",
				Snippet:     "[auth.go:25] (go)\n > 25 | + key := \"AKIAIOSFODNN7EXAMPLE\"\n",
			},
			{
				ID:          "f2",
				Rule:        "xss-injection",
				Severity:    "high",
				File:        "web/handler.js",
				Line:        10,
				Message:     "Unescaped innerHTML assignment",
				Remediation: "Use textContent or DOMPurify",
				Category:    "security",
			},
		},
	}

	htmlOut, err := formatReportHTML(report)
	if err != nil {
		t.Fatalf("formatReportHTML error: %v", err)
	}

	// 1. Structure check
	if !strings.HasPrefix(htmlOut, "<!DOCTYPE html>") {
		t.Errorf("expected HTML doctype")
	}
	if !strings.Contains(htmlOut, "<style>") || !strings.Contains(htmlOut, "</style>") {
		t.Errorf("expected embedded styles")
	}
	if !strings.Contains(htmlOut, "<script>") || !strings.Contains(htmlOut, "</script>") {
		t.Errorf("expected embedded script")
	}

	// 2. Status badge & metadata
	if !strings.Contains(htmlOut, "status-badge failed") {
		t.Errorf("expected failed status badge")
	}
	if !strings.Contains(htmlOut, "run-abc-123") {
		t.Errorf("expected run ID in report")
	}
	if !strings.Contains(htmlOut, "feature/auth") {
		t.Errorf("expected branch in report")
	}

	// 3. Search box & filter controls
	if !strings.Contains(htmlOut, `id="search-box"`) {
		t.Errorf("expected search box with id='search-box'")
	}
	if !strings.Contains(htmlOut, `id="filter-severity"`) {
		t.Errorf("expected severity filter with id='filter-severity'")
	}
	if !strings.Contains(htmlOut, `id="filter-rule"`) {
		t.Errorf("expected rule filter with id='filter-rule'")
	}
	if !strings.Contains(htmlOut, `id="filter-file"`) {
		t.Errorf("expected file filter with id='filter-file'")
	}

	// 4. Collapsible findings details
	if !strings.Contains(htmlOut, `<details class="finding-card"`) {
		t.Errorf("expected <details class=\"finding-card\">")
	}
	if !strings.Contains(htmlOut, `<summary class="finding-summary">`) {
		t.Errorf("expected <summary class=\"finding-summary\">")
	}

	// 5. Snippet embedded
	if !strings.Contains(htmlOut, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("expected snippet text in report")
	}
	if !strings.Contains(htmlOut, "snippet-box") {
		t.Errorf("expected snippet-box container")
	}

	// 6. Remediation box
	if !strings.Contains(htmlOut, "remediation-box") {
		t.Errorf("expected remediation-box in finding details")
	}
}

func TestFormatReportHTMLEscapingXSS(t *testing.T) {
	report := review.Report{
		Summary: "<script>alert('xss-summary')</script>",
		Findings: []review.Finding{
			{
				Rule:        "xss-test",
				Severity:    "high",
				File:        "test<img src=x onerror=alert(1)>.js",
				Line:        1,
				Message:     "<script>alert('xss-msg')</script>",
				Remediation: "<b>Bold fix</b> & safe",
				Snippet:     "<svg onload=alert(2)>",
			},
		},
	}

	htmlOut, err := formatReportHTML(report)
	if err != nil {
		t.Fatalf("formatReportHTML error: %v", err)
	}

	// Raw unescaped payloads must NOT appear
	if strings.Contains(htmlOut, "<script>alert('xss") {
		t.Errorf("unencoded script tag found in HTML")
	}
	if strings.Contains(htmlOut, "<img src=x") {
		t.Errorf("unencoded img tag found in HTML")
	}
	if strings.Contains(htmlOut, "<svg onload=") {
		t.Errorf("unencoded svg tag found in HTML")
	}

	// Escaped entities must appear
	if !strings.Contains(htmlOut, "&lt;script&gt;alert(&#39;xss-msg&#39;)&lt;/script&gt;") {
		t.Errorf("expected escaped message in HTML")
	}
}

func TestFormatFindingsHTMLConvenience(t *testing.T) {
	findings := []review.Finding{
		{Rule: "sec-1", Severity: "medium", File: "a.go", Line: 10, Message: "warning"},
	}
	out, err := formatFindingsHTML(findings)
	if err != nil {
		t.Fatalf("formatFindingsHTML error: %v", err)
	}
	if !strings.Contains(out, "sec-1") || !strings.Contains(out, "a.go:10") {
		t.Errorf("expected finding data in HTML output")
	}
}

func TestFormatFindingsJSONWithSnippet(t *testing.T) {
	findings := []review.Finding{
		{
			Rule:     "rule-1",
			Severity: "high",
			File:     "foo.go",
			Line:     3,
			Message:  "msg",
			Snippet:  "[foo.go:3] (go)\n > 3 | + test()\n",
		},
	}
	out, err := formatFindingsJSON(findings)
	if err != nil {
		t.Fatalf("formatFindingsJSON error: %v", err)
	}
	var items []map[string]interface{}
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if snip, ok := items[0]["snippet"].(string); !ok || !strings.Contains(snip, "foo.go:3") {
		t.Errorf("expected snippet in JSON output, got: %v", items[0]["snippet"])
	}
}

func TestFormatFindingsJSONAndJSONLSignature(t *testing.T) {
	findings := []review.Finding{
		{
			Rule:        "sig-rule",
			Severity:    "high",
			File:        "sig.go",
			Line:        10,
			Message:     "Signature test finding",
			Signature:   "sig-sha256-abcdef1234567890",
			Confidence:  "high",
			Analyzers:   []string{"static", "heuristic"},
			AdvisoryID:  "GHSA-1234",
			AdvisoryIDs: []string{"GHSA-1234", "CVE-2026-9999"},
		},
	}

	// JSON format check
	jsonOut, err := formatFindingsJSON(findings)
	if err != nil {
		t.Fatalf("formatFindingsJSON error: %v", err)
	}
	var jsonItems []map[string]interface{}
	if err := json.Unmarshal([]byte(jsonOut), &jsonItems); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	if jsonItems[0]["signature"] != "sig-sha256-abcdef1234567890" {
		t.Errorf("expected signature in JSON, got %v", jsonItems[0]["signature"])
	}

	// JSONL format check
	jsonlOut, err := formatFindingsJSONL(findings)
	if err != nil {
		t.Fatalf("formatFindingsJSONL error: %v", err)
	}
	var jsonlObj map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(jsonlOut)), &jsonlObj); err != nil {
		t.Fatalf("unmarshal jsonl: %v", err)
	}
	if jsonlObj["signature"] != "sig-sha256-abcdef1234567890" {
		t.Errorf("expected signature in JSONL, got %v", jsonlObj["signature"])
	}
}

func TestFormatReportHTMLGroupedRulesAndMetadata(t *testing.T) {
	report := review.Report{
		Scope:   "staged",
		Passed:  false,
		Summary: "Security audit failed",
		Findings: []review.Finding{
			{
				ID:         "find-grp-1",
				Rule:       "primary-rule",
				Rules:      []string{"primary-rule", "secondary-rule", "tertiary-rule"},
				Analyzers:  []string{"gosec", "gitleaks"},
				Severity:   "critical",
				Confidence: "high",
				File:       "crypto/key.go",
				Line:       42,
				Message:    "Weak encryption key",
				Signature:  "crypto-sig-123",
				Snippet:    "[crypto/key.go:42] (go)\n > 42 | + key := weakKey()\n",
			},
		},
	}

	htmlOut, err := formatReportHTML(report)
	if err != nil {
		t.Fatalf("formatReportHTML error: %v", err)
	}

	// Verify all associated rules are in the dropdown
	if !strings.Contains(htmlOut, `value="primary-rule"`) {
		t.Errorf("expected primary-rule in filter dropdown")
	}
	if !strings.Contains(htmlOut, `value="secondary-rule"`) {
		t.Errorf("expected secondary-rule in filter dropdown")
	}
	if !strings.Contains(htmlOut, `value="tertiary-rule"`) {
		t.Errorf("expected tertiary-rule in filter dropdown")
	}

	// Verify data-rules attribute on finding card
	if !strings.Contains(htmlOut, `data-rules="primary-rule,secondary-rule,tertiary-rule"`) {
		t.Errorf("expected finding card data-rules attribute, got:\n%s", htmlOut)
	}

	// Verify metadata fields rendered
	if !strings.Contains(htmlOut, "Confidence:") || !strings.Contains(htmlOut, "Signature:") {
		t.Errorf("expected Confidence and Signature in HTML metadata row")
	}
	if !strings.Contains(htmlOut, "crypto-sig-123") {
		t.Errorf("expected signature value in HTML")
	}
	if !strings.Contains(htmlOut, "Analyzers:") || !strings.Contains(htmlOut, "gosec, gitleaks") {
		t.Errorf("expected Analyzers in HTML metadata row")
	}

	// Verify stat-card data-sev
	if !strings.Contains(htmlOut, `data-sev="critical"`) {
		t.Errorf("expected data-sev attribute on critical stat card")
	}
}
