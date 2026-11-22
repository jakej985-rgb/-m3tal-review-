package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/prreview"
)

// Client defines the interface for interacting with GitHub Pull Requests.
type Client interface {
	GetPRMetadata(ctx context.Context, owner, repo string, prNumber int) (*PRMetadata, error)
	GetPRDiff(ctx context.Context, owner, repo string, prNumber int) (string, error)
	SubmitReview(ctx context.Context, owner, repo string, prNumber int, headSHA string, report *prreview.PRReviewReport) error
	FindSummaryComment(ctx context.Context, owner, repo string, prNumber int) (int64, error)
	UpdateComment(ctx context.Context, owner, repo string, commentID int64, body string) error
	CreateComment(ctx context.Context, owner, repo string, prNumber int, body string) error
}

// PRMetadata holds key PR details.
type PRMetadata struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	HeadSHA string `json:"head_sha"`
	BaseRef string `json:"base_ref"`
	HeadRef string `json:"head_ref"`
}

// NewClient returns a dual-mode client: direct REST API if token is provided or env GITHUB_TOKEN exists,
// or fallback to gh CLI.
func NewClient(token string) Client {
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token != "" {
		return &RESTClient{
			Token:      token,
			BaseURL:    "https://api.github.com",
			HTTPClient: &http.Client{Timeout: 30 * time.Second},
		}
	}
	return &GHCLIClient{}
}

// RESTClient interacts directly with GitHub REST API via HTTP.
type RESTClient struct {
	Token      string
	BaseURL    string
	HTTPClient *http.Client
}

func (c *RESTClient) doRequest(ctx context.Context, method, endpoint string, reqBody any, headers map[string]string) ([]byte, error) {
	url := fmt.Sprintf("%s%s", c.BaseURL, endpoint)
	var bodyReader io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "m3tal-review")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github api request %s %s: %w", method, endpoint, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github api error (%d %s): %s", resp.StatusCode, resp.Status, string(respBytes))
	}

	return respBytes, nil
}

func (c *RESTClient) GetPRMetadata(ctx context.Context, owner, repo string, prNumber int) (*PRMetadata, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s/pulls/%d", owner, repo, prNumber)
	raw, err := c.doRequest(ctx, http.MethodGet, endpoint, nil, nil)
	if err != nil {
		return nil, err
	}

	var data struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
		Head   struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("unmarshal pr metadata: %w", err)
	}

	return &PRMetadata{
		Number:  data.Number,
		Title:   data.Title,
		HeadSHA: data.Head.SHA,
		BaseRef: data.Base.Ref,
		HeadRef: data.Head.Ref,
	}, nil
}

func (c *RESTClient) GetPRDiff(ctx context.Context, owner, repo string, prNumber int) (string, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s/pulls/%d", owner, repo, prNumber)
	headers := map[string]string{
		"Accept": "application/vnd.github.v3.diff",
	}
	raw, err := c.doRequest(ctx, http.MethodGet, endpoint, nil, headers)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (c *RESTClient) FindSummaryComment(ctx context.Context, owner, repo string, prNumber int) (int64, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s/issues/%d/comments?per_page=100", owner, repo, prNumber)
	raw, err := c.doRequest(ctx, http.MethodGet, endpoint, nil, nil)
	if err != nil {
		return 0, err
	}

	var comments []struct {
		ID   int64  `json:"id"`
		Body string `json:"body"`
	}
	if err := json.Unmarshal(raw, &comments); err != nil {
		return 0, fmt.Errorf("unmarshal comments: %w", err)
	}

	for _, cm := range comments {
		if strings.Contains(cm.Body, prreview.SummaryMarkerTag) {
			return cm.ID, nil
		}
	}
	return 0, nil
}

func (c *RESTClient) UpdateComment(ctx context.Context, owner, repo string, commentID int64, body string) error {
	endpoint := fmt.Sprintf("/repos/%s/%s/issues/comments/%d", owner, repo, commentID)
	payload := map[string]string{"body": body}
	_, err := c.doRequest(ctx, http.MethodPatch, endpoint, payload, nil)
	return err
}

func (c *RESTClient) CreateComment(ctx context.Context, owner, repo string, prNumber int, body string) error {
	endpoint := fmt.Sprintf("/repos/%s/%s/issues/%d/comments", owner, repo, prNumber)
	payload := map[string]string{"body": body}
	_, err := c.doRequest(ctx, http.MethodPost, endpoint, payload, nil)
	return err
}

func (c *RESTClient) SubmitReview(ctx context.Context, owner, repo string, prNumber int, headSHA string, report *prreview.PRReviewReport) error {
	// First, update or create the top-level summary comment in-place
	commentID, err := c.FindSummaryComment(ctx, owner, repo, prNumber)
	if err == nil && commentID > 0 {
		_ = c.UpdateComment(ctx, owner, repo, commentID, report.SummaryMarkdown)
	} else {
		_ = c.CreateComment(ctx, owner, repo, prNumber, report.SummaryMarkdown)
	}

	// Prepare inline review comments
	type reviewComment struct {
		Path string `json:"path"`
		Line int    `json:"line"`
		Side string `json:"side"`
		Body string `json:"body"`
	}

	var apiComments []reviewComment
	for _, ic := range report.InlineComments {
		if ic.Line > 0 && ic.Path != "" {
			apiComments = append(apiComments, reviewComment{
				Path: ic.Path,
				Line: ic.Line,
				Side: "RIGHT",
				Body: ic.Body,
			})
		}
	}

	// If there are inline comments or verdict is REQUEST_CHANGES/APPROVE, submit a PR review
	reviewPayload := map[string]any{
		"event": string(report.Verdict),
		"body":  fmt.Sprintf("🛡️ m3tal-review verdict: **%s** (Quality Grade: %s, %d/100). See top-level summary comment for full details.", report.Verdict, report.Grade.Grade, report.Grade.Score),
	}
	if headSHA != "" {
		reviewPayload["commit_id"] = headSHA
	}
	if len(apiComments) > 0 {
		reviewPayload["comments"] = apiComments
	}

	endpoint := fmt.Sprintf("/repos/%s/%s/pulls/%d/reviews", owner, repo, prNumber)
	_, err = c.doRequest(ctx, http.MethodPost, endpoint, reviewPayload, nil)
	if err != nil && report.Verdict != prreview.VerdictComment && (strings.Contains(err.Error(), "own pull request") || strings.Contains(err.Error(), "Unprocessable Entity")) {
		// GitHub prevents PR authors from submitting REQUEST_CHANGES / APPROVE on their own PR.
		// Fallback to COMMENT event so inline comments and verdict still post successfully.
		reviewPayload["event"] = string(prreview.VerdictComment)
		_, err = c.doRequest(ctx, http.MethodPost, endpoint, reviewPayload, nil)
	}
	return err
}

// GHCLIClient interacts with GitHub via the installed `gh` CLI.
type GHCLIClient struct{}

func (c *GHCLIClient) runGH(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "gh", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("gh %s: %s (%w)", strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return string(out), nil
}

func (c *GHCLIClient) GetPRMetadata(ctx context.Context, owner, repo string, prNumber int) (*PRMetadata, error) {
	target := fmt.Sprintf("%d", prNumber)
	if prNumber <= 0 {
		target = ""
	}
	args := []string{"pr", "view"}
	if target != "" {
		args = append(args, target)
	}
	if owner != "" && repo != "" {
		args = append(args, "--repo", fmt.Sprintf("%s/%s", owner, repo))
	}
	args = append(args, "--json", "number,title,headRefOid,baseRefName,headRefName")

	out, err := c.runGH(ctx, args...)
	if err != nil {
		return nil, err
	}

	var data struct {
		Number      int    `json:"number"`
		Title       string `json:"title"`
		HeadRefOid  string `json:"headRefOid"`
		BaseRefName string `json:"baseRefName"`
		HeadRefName string `json:"headRefName"`
	}
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		return nil, fmt.Errorf("unmarshal gh pr view: %w", err)
	}

	return &PRMetadata{
		Number:  data.Number,
		Title:   data.Title,
		HeadSHA: data.HeadRefOid,
		BaseRef: data.BaseRefName,
		HeadRef: data.HeadRefName,
	}, nil
}

func (c *GHCLIClient) GetPRDiff(ctx context.Context, owner, repo string, prNumber int) (string, error) {
	args := []string{"pr", "diff"}
	if prNumber > 0 {
		args = append(args, fmt.Sprintf("%d", prNumber))
	}
	if owner != "" && repo != "" {
		args = append(args, "--repo", fmt.Sprintf("%s/%s", owner, repo))
	}
	return c.runGH(ctx, args...)
}

func (c *GHCLIClient) FindSummaryComment(ctx context.Context, owner, repo string, prNumber int) (int64, error) {
	endpoint := fmt.Sprintf("repos/%s/%s/issues/%d/comments?per_page=100", owner, repo, prNumber)
	out, err := c.runGH(ctx, "api", endpoint)
	if err != nil {
		return 0, err
	}

	var comments []struct {
		ID   int64  `json:"id"`
		Body string `json:"body"`
	}
	if err := json.Unmarshal([]byte(out), &comments); err != nil {
		return 0, err
	}

	for _, cm := range comments {
		if strings.Contains(cm.Body, prreview.SummaryMarkerTag) {
			return cm.ID, nil
		}
	}
	return 0, nil
}

func (c *GHCLIClient) UpdateComment(ctx context.Context, owner, repo string, commentID int64, body string) error {
	endpoint := fmt.Sprintf("repos/%s/%s/issues/comments/%d", owner, repo, commentID)
	_, err := c.runGH(ctx, "api", "-X", "PATCH", endpoint, "-f", "body="+body)
	return err
}

func (c *GHCLIClient) CreateComment(ctx context.Context, owner, repo string, prNumber int, body string) error {
	endpoint := fmt.Sprintf("repos/%s/%s/issues/%d/comments", owner, repo, prNumber)
	_, err := c.runGH(ctx, "api", "-X", "POST", endpoint, "-f", "body="+body)
	return err
}

func (c *GHCLIClient) SubmitReview(ctx context.Context, owner, repo string, prNumber int, headSHA string, report *prreview.PRReviewReport) error {
	// Update or create summary comment
	commentID, err := c.FindSummaryComment(ctx, owner, repo, prNumber)
	if err == nil && commentID > 0 {
		_ = c.UpdateComment(ctx, owner, repo, commentID, report.SummaryMarkdown)
	} else {
		_ = c.CreateComment(ctx, owner, repo, prNumber, report.SummaryMarkdown)
	}

	// If there are inline comments, prepare review payload for `gh api`
	type reviewComment struct {
		Path string `json:"path"`
		Line int    `json:"line"`
		Side string `json:"side"`
		Body string `json:"body"`
	}
	var apiComments []reviewComment
	for _, ic := range report.InlineComments {
		if ic.Line > 0 && ic.Path != "" {
			apiComments = append(apiComments, reviewComment{
				Path: ic.Path,
				Line: ic.Line,
				Side: "RIGHT",
				Body: ic.Body,
			})
		}
	}

	reviewPayload := map[string]any{
		"event": string(report.Verdict),
		"body":  fmt.Sprintf("🛡️ m3tal-review verdict: **%s** (Quality Grade: %s, %d/100).", report.Verdict, report.Grade.Grade, report.Grade.Score),
	}
	if headSHA != "" {
		reviewPayload["commit_id"] = headSHA
	}
	if len(apiComments) > 0 {
		reviewPayload["comments"] = apiComments
	}

	data, err := json.Marshal(reviewPayload)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("repos/%s/%s/pulls/%d/reviews", owner, repo, prNumber)
	cmd := exec.CommandContext(ctx, "gh", "api", "-X", "POST", endpoint, "--input", "-")
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if report.Verdict != prreview.VerdictComment && (strings.Contains(string(out), "own pull request") || strings.Contains(string(out), "Unprocessable Entity")) {
			reviewPayload["event"] = string(prreview.VerdictComment)
			if retryData, retryErr := json.Marshal(reviewPayload); retryErr == nil {
				retryCmd := exec.CommandContext(ctx, "gh", "api", "-X", "POST", endpoint, "--input", "-")
				retryCmd.Stdin = bytes.NewReader(retryData)
				if _, retryErr := retryCmd.CombinedOutput(); retryErr == nil {
					return nil
				}
			}
		}
		return fmt.Errorf("submit review via gh api: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}
