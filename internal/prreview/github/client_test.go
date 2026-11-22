package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/prreview"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestParseBotComment(t *testing.T) {
	cases := []struct {
		input       string
		expectedNil bool
		expectedCmd BotCommandKind
		expectedArg string
	}{
		{"Hello world", true, "", ""},
		{"@m3tal-review review", false, CommandReview, ""},
		{"@m3tal-review", false, CommandReview, ""},
		{"@m3tal-review explain pipe-to-shell", false, CommandExplain, "pipe-to-shell"},
		{"@m3tal-review resolve", false, CommandResolve, ""},
		{"@m3tal-review help", false, CommandHelp, ""},
		{"@m3tal-review unknown-arg", false, CommandUnknown, "unknown-arg"},
	}

	for _, c := range cases {
		cmd := ParseBotComment(c.input)
		if c.expectedNil {
			if cmd != nil {
				t.Errorf("expected nil for %q, got %+v", c.input, cmd)
			}
			continue
		}
		if cmd == nil {
			t.Fatalf("expected non-nil cmd for %q", c.input)
		}
		if cmd.Kind != c.expectedCmd {
			t.Errorf("input %q: expected cmd %s, got %s", c.input, c.expectedCmd, cmd.Kind)
		}
		if cmd.Argument != c.expectedArg {
			t.Errorf("input %q: expected arg %s, got %s", c.input, c.expectedArg, cmd.Argument)
		}
	}
}

func TestFormatExplainResponse(t *testing.T) {
	resp := FormatExplainResponse("pipe-to-shell")
	if !strings.Contains(resp, "pipe-to-shell") {
		t.Errorf("expected explanation to contain rule name, got %s", resp)
	}

	unknown := FormatExplainResponse("non-existent-rule-12345")
	if !strings.Contains(unknown, "not recognized") {
		t.Errorf("expected not recognized message, got %s", unknown)
	}
}

func TestRESTClientMock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/pulls/42") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"number": 42,
				"title":  "Test PR",
				"head":   map[string]string{"sha": "abc1234", "ref": "feature"},
				"base":   map[string]string{"ref": "main"},
			})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/issues/42/comments") {
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode([]map[string]any{
					{"id": 101, "body": "regular comment"},
					{"id": 102, "body": prreview.SummaryMarkerTag + "\nExisting summary"},
				})
				return
			}
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{"id": 103})
				return
			}
		}
		if strings.HasSuffix(r.URL.Path, "/issues/comments/102") && r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 102})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/pulls/42/reviews") && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 201})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := &RESTClient{
		Token:      "mock-token",
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	}

	ctx := context.Background()

	meta, err := client.GetPRMetadata(ctx, "owner", "repo", 42)
	if err != nil {
		t.Fatalf("GetPRMetadata error: %v", err)
	}
	if meta.Number != 42 || meta.HeadSHA != "abc1234" {
		t.Errorf("unexpected metadata: %+v", meta)
	}

	commentID, err := client.FindSummaryComment(ctx, "owner", "repo", 42)
	if err != nil {
		t.Fatalf("FindSummaryComment error: %v", err)
	}
	if commentID != 102 {
		t.Errorf("expected comment ID 102, got %d", commentID)
	}

	report := &prreview.PRReviewReport{
		SummaryMarkdown: prreview.SummaryMarkerTag + "\nNew summary",
		Verdict:         prreview.VerdictRequestChanges,
		Grade:           review.GradeResult{Grade: "B", Score: 85},
		InlineComments: []prreview.InlineComment{
			{Path: "pkg/auth/token.go", Line: 10, Body: "test comment"},
		},
	}

	if err := client.SubmitReview(ctx, "owner", "repo", 42, "abc1234", report); err != nil {
		t.Fatalf("SubmitReview error: %v", err)
	}
}
