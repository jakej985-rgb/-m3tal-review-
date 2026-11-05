package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// postPRComment publishes a findings summary as a comment on the pull
// request associated with the current branch, using the GitHub CLI (`gh`)
// so no token handling lives in this tool. Requires `gh` to be installed
// and authenticated and the checkout to be inside a PR.
func postPRComment(repositoryRoot string, findings []review.Finding) error {
	if _, err := exec.LookPath("gh"); err != nil {
		return fmt.Errorf("pr-comment requires the GitHub CLI (gh) on PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	prNumber, err := ghOutput(ctx, repositoryRoot, "pr", "view", "--json", "number", "--jq", ".number")
	if err != nil {
		return fmt.Errorf("pr-comment: no pull request for current branch (is gh authenticated and the branch pushed?): %w", err)
	}
	prNumber = strings.TrimSpace(prNumber)
	if prNumber == "" || prNumber == "null" {
		return fmt.Errorf("pr-comment: no pull request found for the current branch")
	}

	body := buildPRCommentBody(findings)
	bodyPath := filepath.Join(os.TempDir(), fmt.Sprintf("m3tal-review-pr-%d.md", time.Now().UnixNano()))
	if err := os.WriteFile(bodyPath, []byte(body), 0o600); err != nil {
		return err
	}
	defer os.Remove(bodyPath)

	if _, err := ghOutput(ctx, repositoryRoot, "pr", "comment", prNumber, "--body-file", bodyPath); err != nil {
		return fmt.Errorf("pr-comment: %w", err)
	}
	return nil
}

func ghOutput(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "gh", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("gh %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// buildPRCommentBody renders findings as a compact markdown comment.
func buildPRCommentBody(findings []review.Finding) string {
	var b strings.Builder
	b.WriteString("## m3tal-review findings\n\n")
	if len(findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	var sevs []string
	for sev := range counts {
		sevs = append(sevs, sev)
	}
	sort.Slice(sevs, func(i, j int) bool { return severityRank(sevs[i]) > severityRank(sevs[j]) })
	parts := make([]string, 0, len(sevs))
	for _, sev := range sevs {
		parts = append(parts, fmt.Sprintf("%d %s", counts[sev], sev))
	}
	fmt.Fprintf(&b, "**%d finding(s)** — %s\n\n", len(findings), strings.Join(parts, ", "))

	const maxRows = 50
	shown := findings
	if len(shown) > maxRows {
		shown = shown[:maxRows]
	}
	b.WriteString("| Severity | Rule | File:Line | Message |\n|---|---|---|---|\n")
	for _, f := range shown {
		msg := strings.ReplaceAll(f.Message, "|", "\\|")
		if len(msg) > 120 {
			msg = msg[:117] + "..."
		}
		fmt.Fprintf(&b, "| %s | `%s` | `%s:%d` | %s |\n", f.Severity, f.Rule, f.File, f.Line, msg)
	}
	if len(findings) > maxRows {
		fmt.Fprintf(&b, "\n_…and %d more (see full report in workflow logs)._\n", len(findings)-maxRows)
	}
	b.WriteString("\n<sub>Deterministic heuristic review — not a complete security analysis.</sub>\n")
	return b.String()
}
