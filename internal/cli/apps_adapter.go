package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/apps"
	"github.com/jakej985-rgb/m3tal-review/internal/git"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
	"github.com/jakej985-rgb/m3tal-review/protocol"
)

func shouldRunApps(repoRoot string, options reviewOptions) bool {
	if options.NoApps {
		return false
	}
	if options.Apps || len(options.AppPaths) > 0 {
		return true
	}
	discovered, _, err := apps.Discover(context.Background(), apps.RunConfig{Root: repoRoot})
	return err == nil && len(discovered) > 0
}

func runAppsForReview(repoRoot string, options reviewOptions, diff string, stagedFiles []string, statuses map[string]string) ([]review.Finding, []string, []review.CheckResult, []review.AppRun, map[string]bool, bool, error) {
	addedByFile := make(map[string][]int)
	for _, fd := range review.ParseDiff(diff) {
		addedByFile[fd.Path] = fd.AddedLines
	}

	files := make([]protocol.File, 0, len(stagedFiles))
	useWorktree := options.Base != "" || options.Unstaged
	for _, rel := range stagedFiles {
		status := statuses[rel]
		if status == "" {
			status = "modified"
		}
		added := addedByFile[rel]
		if status != "deleted" && len(added) == 0 {
			continue
		}
		var content string
		if status != "deleted" {
			if useWorktree {
				data, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
				if err == nil {
					content = string(data)
				}
			} else {
				c, err := git.StagedFileContent(repoRoot, rel)
				if err == nil {
					content = string(c)
				}
			}
		}
		files = append(files, protocol.File{
			Path:       rel,
			Status:     status,
			AddedLines: added,
			Content:    content,
		})
	}

	rep, err := apps.Run(context.Background(), apps.RunConfig{
		Root:     repoRoot,
		Scope:    "staged",
		Mode:     "review",
		AppPaths: options.AppPaths,
		Timeout:  options.AppTimeout,
	}, files)
	if err != nil {
		return nil, nil, nil, nil, nil, true, err
	}

	outFindings, checks, appRuns, unanalyzed, incomplete := collectAppOutputs(rep, options.Only, options.Skip)
	return outFindings, unanalyzed, checks, appRuns, rep.RoutedFiles, incomplete, nil
}

func collectAppOutputs(rep apps.RunReport, only, skip []string) ([]review.Finding, []review.CheckResult, []review.AppRun, []string, bool) {
	var outFindings []review.Finding
	for _, f := range rep.Findings {
		if ruleAllowed(only, skip, f.Rule) {
			outFindings = append(outFindings, protocolToReviewFinding(f))
		}
	}

	unanalyzed := append([]string(nil), rep.UnanalyzedFiles...)
	incomplete := rep.ExitCode >= protocol.ExitError || len(rep.MissingClaims) > 0

	var checks []review.CheckResult
	for _, mc := range rep.MissingClaims {
		checks = append(checks, review.CheckResult{
			Name:    "app:" + mc.App,
			Status:  "failed",
			Message: mc.String(),
		})
	}
	var appRuns []review.AppRun
	for _, ar := range rep.Apps {
		status := "passed"
		msg := fmt.Sprintf("%s %s (%d findings)", ar.App.Name, ar.App.Version, len(ar.Output.Findings))
		errText := ""
		if ar.Status != "ok" {
			status = "failed"
			incomplete = true
			msg = fmt.Sprintf("%s failed: %v", ar.App.Name, ar.Err)
			errText = ar.Err.Error()
			fmt.Fprintln(os.Stderr, msg)
		}
		checks = append(checks, review.CheckResult{
			Name:    "app:" + ar.App.Name,
			Status:  status,
			Message: msg,
		})
		appRuns = append(appRuns, review.AppRun{
			Name:       ar.App.Name,
			Version:    ar.App.Version,
			Status:     ar.Status,
			ExitCode:   ar.ExitCode,
			DurationMs: ar.Duration.Milliseconds(),
			Files:      ar.Output.Stats.Files,
			Rules:      ar.Output.Stats.Rules,
			Findings:   len(ar.Output.Findings),
			Error:      errText,
		})
	}
	return outFindings, checks, appRuns, unanalyzed, incomplete
}

func stripRoutedFilesFromDiff(diff string, routed map[string]bool) string {
	if len(routed) == 0 || diff == "" {
		return diff
	}
	const marker = "diff --git "
	var out strings.Builder
	rest := diff
	for {
		idx := strings.Index(rest, marker)
		if idx < 0 {
			out.WriteString(rest)
			break
		}
		out.WriteString(rest[:idx])
		rest = rest[idx:]
		next := strings.Index(rest[len(marker):], marker)
		var chunk string
		if next < 0 {
			chunk = rest
			rest = ""
		} else {
			end := len(marker) + next
			chunk = rest[:end]
			rest = rest[end:]
		}
		if !routed[diffChunkPath(chunk)] {
			out.WriteString(chunk)
		}
		if rest == "" {
			break
		}
	}
	return out.String()
}

func diffChunkPath(chunk string) string {
	firstLine, _, _ := strings.Cut(chunk, "\n")
	if idx := strings.LastIndex(firstLine, " b/"); idx >= 0 {
		return strings.TrimSpace(firstLine[idx+3:])
	}
	return ""
}

func protocolToReviewFinding(f protocol.Finding) review.Finding {
	return review.Finding{
		Rule:        f.Rule,
		Category:    f.Category,
		Severity:    f.Severity,
		Confidence:  f.Confidence,
		File:        f.File,
		Line:        f.Line,
		Message:     f.Message,
		Remediation: f.Remediation,
		Signature:   f.Fingerprint,
		Snippet:     f.Evidence,
	}
}

func runAppsForAudit(repoRoot string, options auditOptions, reviewedFiles []string) ([]review.Finding, []string, []review.CheckResult, []review.AppRun, bool, error) {
	files := make([]protocol.File, 0, len(reviewedFiles))
	for _, rel := range reviewedFiles {
		data, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		files = append(files, protocol.File{
			Path:    rel,
			Status:  "modified",
			Content: string(data),
		})
	}

	rep, err := apps.Run(context.Background(), apps.RunConfig{
		Root:     repoRoot,
		Scope:    "working-tree",
		Mode:     "audit",
		AppPaths: options.AppPaths,
		Timeout:  options.AppTimeout,
	}, files)
	if err != nil {
		return nil, nil, nil, nil, true, err
	}

	outFindings, checks, appRuns, unanalyzed, incomplete := collectAppOutputs(rep, options.Only, options.Skip)
	return outFindings, unanalyzed, checks, appRuns, incomplete, nil
}

func appCacheSalt(repoRoot string, appPaths []string) string {
	discovered, _, err := apps.Discover(context.Background(), apps.RunConfig{
		Root:     repoRoot,
		AppPaths: appPaths,
	})
	if err != nil || len(discovered) == 0 {
		return ""
	}
	var b strings.Builder
	for _, a := range discovered {
		b.WriteString(a.Name)
		b.WriteByte('@')
		b.WriteString(a.Version)
		b.WriteByte(':')
		for _, r := range a.Rules {
			b.WriteString(r.ID)
			b.WriteByte(',')
		}
		b.WriteByte(';')
	}
	return b.String()
}
