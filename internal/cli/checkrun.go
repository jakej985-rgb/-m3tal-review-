package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// postCheckRun publishes review findings as a GitHub Check Run with
// annotations. Requires GITHUB_TOKEN, GITHUB_REPOSITORY (owner/repo),
// and GITHUB_SHA (or --sha). No-op-safe: returns an error describing the
// missing configuration so callers can warn instead of failing.
func postCheckRun(findings []review.Finding, sha string) error {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	repo := os.Getenv("GITHUB_REPOSITORY")
	if token == "" || repo == "" {
		return fmt.Errorf("check-run requires GITHUB_TOKEN and GITHUB_REPOSITORY")
	}
	if sha == "" {
		sha = os.Getenv("GITHUB_SHA")
	}
	if sha == "" {
		return fmt.Errorf("check-run requires a commit SHA (GITHUB_SHA or --sha)")
	}

	type annotation struct {
		Path            string `json:"path"`
		StartLine       int    `json:"start_line"`
		EndLine         int    `json:"end_line"`
		AnnotationLevel string `json:"annotation_level"`
		Message         string `json:"message"`
		Title           string `json:"title"`
	}
	level := func(s string) string {
		switch s {
		case "critical", "high":
			return "failure"
		case "medium":
			return "warning"
		default:
			return "notice"
		}
	}
	var anns []annotation
	for _, f := range findings {
		if len(anns) >= 50 { // GitHub caps annotations per request
			break
		}
		line := f.Line
		if line < 1 {
			line = 1
		}
		anns = append(anns, annotation{
			Path: f.File, StartLine: line, EndLine: line,
			AnnotationLevel: level(f.Severity),
			Message:         f.Message,
			Title:           f.Rule,
		})
	}
	conclusion := "success"
	if len(findings) > 0 {
		conclusion = "neutral"
	}
	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "high" {
			conclusion = "failure"
			break
		}
	}
	payload := map[string]any{
		"name":       "m3tal-review",
		"head_sha":   sha,
		"status":     "completed",
		"conclusion": conclusion,
		"output": map[string]any{
			"title":       fmt.Sprintf("m3tal-review: %d finding(s)", len(findings)),
			"summary":     fmt.Sprintf("Deterministic heuristic review found %d issue(s).", len(findings)),
			"annotations": anns,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost,
		"https://api.github.com/repos/"+repo+"/check-runs", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("GitHub API %s: %s", resp.Status, string(b))
	}
	return nil
}
