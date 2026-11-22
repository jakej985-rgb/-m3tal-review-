package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
	"github.com/jakej985-rgb/m3tal-review/internal/prreview"
	gh "github.com/jakej985-rgb/m3tal-review/internal/prreview/github"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

type prReviewOptions struct {
	Base          string
	PRNumber      int
	Repo          string
	Interactive   bool
	PostGH        bool
	CommentOnly   bool
	OutputFile    string
	HandleComment string
}

func parsePRReviewOptions(args []string) (prReviewOptions, error) {
	opts := prReviewOptions{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--base":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--base requires an argument")
			}
			opts.Base = args[i+1]
			i++
		case strings.HasPrefix(arg, "--base="):
			opts.Base = strings.TrimPrefix(arg, "--base=")
		case arg == "--pr":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--pr requires an integer argument")
			}
			num, err := strconv.Atoi(args[i+1])
			if err != nil {
				return opts, fmt.Errorf("invalid --pr number: %w", err)
			}
			opts.PRNumber = num
			i++
		case strings.HasPrefix(arg, "--pr="):
			num, err := strconv.Atoi(strings.TrimPrefix(arg, "--pr="))
			if err != nil {
				return opts, fmt.Errorf("invalid --pr number: %w", err)
			}
			opts.PRNumber = num
		case arg == "--repo":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--repo requires owner/repo argument")
			}
			opts.Repo = args[i+1]
			i++
		case strings.HasPrefix(arg, "--repo="):
			opts.Repo = strings.TrimPrefix(arg, "--repo=")
		case arg == "--interactive", arg == "-i":
			opts.Interactive = true
		case arg == "--post-gh":
			opts.PostGH = true
		case arg == "--comment-only":
			opts.CommentOnly = true
		case arg == "--output", arg == "-o":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--output requires a file path")
			}
			opts.OutputFile = args[i+1]
			i++
		case strings.HasPrefix(arg, "--output="):
			opts.OutputFile = strings.TrimPrefix(arg, "--output=")
		case arg == "--handle-comment":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--handle-comment requires comment body")
			}
			opts.HandleComment = args[i+1]
			i++
		case strings.HasPrefix(arg, "--handle-comment="):
			opts.HandleComment = strings.TrimPrefix(arg, "--handle-comment=")
		default:
			return opts, fmt.Errorf("unknown pr-review option: %s", arg)
		}
	}
	return opts, nil
}

func runPRReview(args []string) error {
	opts, err := parsePRReviewOptions(args)
	if err != nil {
		return err
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	repositoryRoot, err := git.RepositoryRoot(workingDir)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ghClient := gh.NewClient("")

	owner, repo := resolveRepoOwnerAndName(opts.Repo, repositoryRoot)
	prNum := opts.PRNumber
	if prNum <= 0 {
		prNum = resolveCurrentPRNumber(ctx, ghClient, owner, repo)
	}

	// Handle PR comment triggers if specified
	if opts.HandleComment != "" {
		botCmd := gh.ParseBotComment(opts.HandleComment)
		if botCmd != nil && botCmd.Kind != gh.CommandReview {
			if owner != "" && repo != "" && prNum > 0 {
				return gh.HandleBotComment(ctx, ghClient, owner, repo, prNum, botCmd)
			}
			return fmt.Errorf("could not resolve PR metadata for comment command")
		}
	}

	var prMeta *gh.PRMetadata
	if prNum > 0 && owner != "" && repo != "" {
		prMeta, _ = ghClient.GetPRMetadata(ctx, owner, repo, prNum)
	}

	// Resolve Base Ref
	baseRef := opts.Base
	if baseRef == "" && prMeta != nil && prMeta.BaseRef != "" {
		testRef := "origin/" + prMeta.BaseRef
		cmd := exec.Command("git", "-C", repositoryRoot, "rev-parse", "--verify", testRef)
		if cmd.Run() == nil {
			baseRef = testRef
		} else {
			baseRef = prMeta.BaseRef
		}
	}
	if baseRef == "" {
		baseRef = detectDefaultBaseRef(repositoryRoot)
	}

	// Compute Diff
	diff, err := getUnifiedDiff(repositoryRoot, baseRef)
	if err != nil {
		return fmt.Errorf("get diff: %w", err)
	}
	if strings.TrimSpace(diff) == "" && prNum > 0 && owner != "" && repo != "" {
		// Fallback to fetching diff directly from GitHub API
		if remoteDiff, err := ghClient.GetPRDiff(ctx, owner, repo, prNum); err == nil && strings.TrimSpace(remoteDiff) != "" {
			diff = remoteDiff
		}
	}
	if strings.TrimSpace(diff) == "" {
		fmt.Println("No modifications detected to review.")
		return nil
	}

	fileDiffs, err := prreview.ParseUnifiedDiff(diff)
	if err != nil {
		return fmt.Errorf("parse diff: %w", err)
	}

	// Run deterministic rule checks
	rules := defaultRulesWithOptions(repositoryRoot, false)
	engine := review.NewEngine(rules...)
	findings := engine.Run(diff)
	findings = review.ApplyFindingFilters(diff, findings, repositoryRoot, baseRef != "")

	// Generate AI-like PR Review
	formatOpts := prreview.FormatOptions{
		CommentOnly: opts.CommentOnly,
		RepoRoot:    repositoryRoot,
	}

	report, err := prreview.GeneratePRReview(findings, fileDiffs, formatOpts)
	if err != nil {
		return fmt.Errorf("generate pr review: %w", err)
	}

	// Output to file if requested
	if opts.OutputFile != "" {
		outPath := opts.OutputFile
		if !filepath.IsAbs(outPath) {
			outPath = filepath.Join(workingDir, outPath)
		}
		if err := os.WriteFile(outPath, []byte(report.SummaryMarkdown), 0o644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		fmt.Printf("PR review report saved to %s\n", outPath)
	}

	// Print summary to terminal
	fmt.Println(report.SummaryMarkdown)

	// Interactive suggestion mode
	if opts.Interactive && len(report.InlineComments) > 0 {
		runInteractiveSuggestions(repositoryRoot, report.InlineComments)
	}

	// Post to GitHub PR if requested
	if opts.PostGH {
		if owner == "" || repo == "" || prNum <= 0 {
			return fmt.Errorf("cannot post to GitHub: missing repository (owner/repo) or PR number; use --repo and --pr")
		}

		headSHA := ""
		if prMeta != nil && prMeta.HeadSHA != "" {
			headSHA = prMeta.HeadSHA
		} else {
			meta, err := ghClient.GetPRMetadata(ctx, owner, repo, prNum)
			if err == nil && meta != nil {
				headSHA = meta.HeadSHA
			}
		}

		fmt.Printf("Submitting review to GitHub %s/%s PR #%d...\n", owner, repo, prNum)
		if err := ghClient.SubmitReview(ctx, owner, repo, prNum, headSHA, report); err != nil {
			return fmt.Errorf("submit github review: %w", err)
		}
		fmt.Printf("✅ Successfully submitted review to GitHub PR #%d (%s, Grade: %s).\n",
			prNum, report.Verdict, report.Grade.Grade)
	}

	if report.Verdict == prreview.VerdictRequestChanges && !opts.CommentOnly {
		return fmt.Errorf("review failed quality gate: %d critical/high issue(s) detected",
			report.CriticalCount+report.HighCount)
	}

	return nil
}

func detectDefaultBaseRef(repoDir string) string {
	candidates := []string{"origin/main", "origin/master", "main", "master", "HEAD~1"}
	for _, ref := range candidates {
		cmd := exec.Command("git", "-C", repoDir, "rev-parse", "--verify", ref)
		if err := cmd.Run(); err == nil {
			return ref
		}
	}
	return ""
}

func getUnifiedDiff(repoDir, baseRef string) (string, error) {
	var cmd *exec.Cmd
	if baseRef != "" {
		cmd = exec.Command("git", "-C", repoDir, "diff", baseRef, "--unified=3", "--no-color")
	} else {
		// Fallback to staged changes
		cmd = exec.Command("git", "-C", repoDir, "diff", "--staged", "--unified=3", "--no-color")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git diff: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return string(out), nil
}

func resolveRepoOwnerAndName(explicitRepo, repoDir string) (string, string) {
	if explicitRepo != "" {
		parts := strings.Split(explicitRepo, "/")
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
	}

	if envRepo := os.Getenv("GITHUB_REPOSITORY"); envRepo != "" {
		parts := strings.Split(envRepo, "/")
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
	}

	// Try git remote get-url origin
	cmd := exec.Command("git", "-C", repoDir, "remote", "get-url", "origin")
	out, err := cmd.Output()
	if err == nil {
		urlStr := strings.TrimSpace(string(out))
		// e.g. git@github.com:owner/repo.git or https://github.com/owner/repo.git
		re := regexp.MustCompile(`github\.com[:/]([^/]+)/([^/\.]+)(?:\.git)?`)
		matches := re.FindStringSubmatch(urlStr)
		if len(matches) == 3 {
			return matches[1], matches[2]
		}
	}

	return "", ""
}

func resolveCurrentPRNumber(ctx context.Context, client gh.Client, owner, repo string) int {
	if envPR := os.Getenv("GITHUB_PR_NUMBER"); envPR != "" {
		if n, err := strconv.Atoi(envPR); err == nil {
			return n
		}
	}
	// Try gh CLI
	meta, err := client.GetPRMetadata(ctx, owner, repo, 0)
	if err == nil && meta != nil {
		return meta.Number
	}
	return 0
}

func runInteractiveSuggestions(repoDir string, comments []prreview.InlineComment) {
	reader := bufio.NewReader(os.Stdin)
	var fixable []prreview.InlineComment
	for _, c := range comments {
		if c.HasFixPatch {
			fixable = append(fixable, c)
		}
	}

	if len(fixable) == 0 {
		return
	}

	fmt.Printf("\n💡 Found %d interactive suggestion(s):\n", len(fixable))
	for i, c := range fixable {
		fmt.Printf("\n[%d/%d] %s:%d — Rule `%s` (%s)\n",
			i+1, len(fixable), c.Path, c.Line, c.Rule, strings.ToUpper(c.Severity))
		fmt.Println("--------------------------------------------------")
		fmt.Println(c.Body)
		fmt.Println("--------------------------------------------------")
		fmt.Print("Action: [a] Apply suggestion, [s] Skip, [e] Explain rule, [q] Quit: ")

		input, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		choice := strings.ToLower(strings.TrimSpace(input))
		switch choice {
		case "a", "apply":
			fmt.Printf("Applying suggestion to %s...\n", c.Path)
			// Apply the suggestion to the file
			if err := applyInlineSuggestion(repoDir, c); err != nil {
				fmt.Printf("Failed to apply suggestion: %v\n", err)
			} else {
				fmt.Printf("✅ Applied suggestion to %s:%d.\n", c.Path, c.Line)
			}
		case "e", "explain":
			doc := prreview.LookupRule(c.Rule)
			if doc != nil {
				fmt.Printf("\n📖 Rationale: %s\nRemediation: %s\n", doc.Rationale, doc.Remediation)
			} else {
				fmt.Println("No additional documentation found for rule.")
			}
		case "q", "quit":
			fmt.Println("Exiting interactive suggestion triage.")
			return
		default:
			fmt.Println("Skipping.")
		}
	}
}

func applyInlineSuggestion(repoDir string, comment prreview.InlineComment) error {
	filePath := filepath.Join(repoDir, comment.Path)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Extract suggestion text from comment body
	startTag := "```suggestion\n"
	endTag := "\n```"
	startIdx := strings.Index(comment.Body, startTag)
	if startIdx == -1 {
		return fmt.Errorf("no suggestion block found in comment")
	}
	startIdx += len(startTag)
	endIdx := strings.Index(comment.Body[startIdx:], endTag)
	if endIdx == -1 {
		return fmt.Errorf("unclosed suggestion block")
	}
	suggestion := comment.Body[startIdx : startIdx+endIdx]
	suggestion = strings.ReplaceAll(suggestion, "\r\n", "\n")

	// Replace the target line in file
	contentStr := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(contentStr, "\n")
	if comment.Line <= 0 || comment.Line > len(lines) {
		return fmt.Errorf("line %d out of bounds (1..%d)", comment.Line, len(lines))
	}

	targetIdx := comment.Line - 1
	var newLines []string
	newLines = append(newLines, lines[:targetIdx]...)
	newLines = append(newLines, strings.Split(suggestion, "\n")...)
	if targetIdx+1 < len(lines) {
		newLines = append(newLines, lines[targetIdx+1:]...)
	}

	return os.WriteFile(filePath, []byte(strings.Join(newLines, "\n")), 0o644)
}
