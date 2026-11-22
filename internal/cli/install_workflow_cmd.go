package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
)

const defaultWorkflowYAML = `name: m3tal-review

on:
  pull_request:
    types: [opened, synchronize, reopened]
  issue_comment:
    types: [created]

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  review:
    name: Pure-Code AI-Like Review
    runs-on: ubuntu-latest
    if: |
      github.event_name == 'pull_request' ||
      (github.event_name == 'issue_comment' &&
       github.event.issue.pull_request &&
       contains(github.event.comment.body, '@m3tal-review'))
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.23'
          cache: true

      - name: Install m3tal-review
        run: |
          go build -o /usr/local/bin/m3tal-review ./cmd/m3tal-review

      - name: Run Review or Bot Command
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_REPOSITORY: ${{ github.repository }}
        run: |
          if [ "${{ github.event_name }}" = "issue_comment" ]; then
            m3tal-review pr-review \
              --pr="${{ github.event.issue.number }}" \
              --handle-comment="${{ github.event.comment.body }}" \
              --post-gh
          else
            m3tal-review pr-review \
              --base="origin/${{ github.base_ref }}" \
              --pr="${{ github.event.pull_request.number }}" \
              --post-gh
          fi
`

func runInstallWorkflow(args []string) error {
	force := false
	for _, a := range args {
		if a == "--force" || a == "-f" {
			force = true
		}
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	repoRoot, err := git.RepositoryRoot(workingDir)
	if err != nil {
		return err
	}

	workflowDir := filepath.Join(repoRoot, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		return fmt.Errorf("create workflow directory: %w", err)
	}

	workflowPath := filepath.Join(workflowDir, "m3tal-review.yml")
	if _, err := os.Stat(workflowPath); err == nil && !force {
		return fmt.Errorf("workflow file %s already exists; use --force to overwrite", workflowPath)
	}

	if err := os.WriteFile(workflowPath, []byte(defaultWorkflowYAML), 0o644); err != nil {
		return fmt.Errorf("write workflow file: %w", err)
	}

	fmt.Printf("✅ Successfully installed GitHub Actions review workflow:\n   %s\n", workflowPath)
	return nil
}
