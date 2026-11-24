package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func showReport(runID string) error {
	if !review.IsValidRunID(runID) {
		return fmt.Errorf("invalid run ID %q: expected 16 lowercase hexadecimal characters", runID)
	}

	if runID == "" {
		return fmt.Errorf("run ID cannot be empty")
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	repositoryRoot, err := git.RepositoryRoot(workingDir)
	if err != nil {
		return err
	}

	reportPath := filepath.Join(
		repositoryRoot,
		".m3tal-review",
		"reports",
		runID+".json",
	)
	if err := ensureReviewStorageSafe(repositoryRoot, reportPath); err != nil {
		return err
	}

	report, err := review.ReadReport(reportPath)
	if err != nil {
		return err
	}

	fmt.Println("M3TAL Review Report")
	fmt.Println("Run ID:", displayText(report.RunID))
	fmt.Println("Repository:", displayText(report.Repository))
	fmt.Println("Branch:", displayText(report.Branch))
	if report.Grade != nil {
		fmt.Printf("Grade: %s (%d/100)\n", report.Grade.Grade, report.Grade.Score)
	}
	fmt.Println("Summary:", displayText(report.Summary))
	fmt.Println("Report:", displayText(reportPath))
	printFindingChanges(report.FindingChanges)
	if len(report.UnanalyzedFiles) > 0 {
		fmt.Println("Not fully analyzed (binary, unsupported source language, submodule, or file-mode changes):")
		for _, file := range report.UnanalyzedFiles {
			fmt.Println("  ", displayText(file))
		}
	}

	if len(report.Findings) == 0 {
		fmt.Println("Findings: (none)")
		return nil
	}

	fmt.Println("Findings:")

	for _, finding := range report.Findings {
		location := displayText(finding.File)
		if finding.Line > 0 {
			location = fmt.Sprintf("%s:%d", location, finding.Line)
		}
		fmt.Printf(
			"[%s] %s: %s (%s)\n",
			displayText(finding.Severity),
			location,
			displayText(finding.Message),
			displayText(finding.Rule),
		)
		if finding.Remediation != "" {
			fmt.Printf("  Remediation: %s\n", displayText(finding.Remediation))
		}
	}

	return nil
}

func runHistoryCommand(commandArgs []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	repositoryRoot, err := git.RepositoryRoot(workingDir)
	if err != nil {
		return err
	}

	historyPath := filepath.Join(
		repositoryRoot,
		".m3tal-review",
		"history.jsonl",
	)
	if err := ensureReviewStorageSafe(repositoryRoot, historyPath); err != nil {
		return err
	}

	if len(commandArgs) >= 1 && commandArgs[0] == "prune" {
		return commandHistoryPrune(repositoryRoot, commandArgs[1:])
	}

	entries, err := review.ReadHistory(historyPath)
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		fmt.Println("No review history found.")
		return nil
	}

	// history show <run-id> / history <run-id> prints a stored report.
	if len(commandArgs) >= 1 && (commandArgs[0] == "show" || !strings.HasPrefix(commandArgs[0], "-")) {
		runID := commandArgs[0]
		rest := commandArgs[1:]
		if runID == "show" {
			if len(rest) < 1 {
				return fmt.Errorf("usage: m3tal-review history show <run-id> [--format json]")
			}
			runID = rest[0]
			rest = rest[1:]
		}
		format := "text"
		for i := 0; i < len(rest); i++ {
			if rest[i] == "--format" {
				if i+1 >= len(rest) || (rest[i+1] != "json" && rest[i+1] != "jsonl" && rest[i+1] != "html") {
					return fmt.Errorf("usage: m3tal-review history show <run-id> [--format json|jsonl|html]")
				}
				format = rest[i+1]
			}
		}
		return commandHistoryShowFormat(repositoryRoot, runID, format)
	}

	// Optional filters: history [--last N] [--status S] [--scope S] [--grep text] [--format json]
	last, statusFilter, scopeFilter, grepFilter := 0, "", "", ""
	formatJSON := false
	for i := 0; i < len(commandArgs); i++ {
		arg := commandArgs[i]
		if i+1 >= len(commandArgs) {
			return fmt.Errorf("history option %q requires a value", arg)
		}
		i++
		v := commandArgs[i]
		switch arg {
		case "--last":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return fmt.Errorf("invalid --last %q", v)
			}
			last = n
		case "--status":
			statusFilter = v
		case "--scope":
			scopeFilter = v
		case "--grep":
			grepFilter = strings.ToLower(v)
		case "--format":
			if v != "json" {
				return fmt.Errorf("invalid --format %q; expected json", v)
			}
			formatJSON = true
		default:
			return fmt.Errorf("unknown history option %q", arg)
		}
	}

	shown := 0
	var jsonOut []review.HistoryEntry
	if formatJSON {
		jsonOut = []review.HistoryEntry{}
	} else {
		fmt.Println("M3TAL Review History")
	}
	// Entries are chronological; --last shows the most recent N.
	for idx := len(entries) - 1; idx >= 0; idx-- {
		entry := entries[idx]
		if statusFilter != "" && entry.Status != statusFilter {
			continue
		}
		if scopeFilter != "" && entry.Scope != scopeFilter {
			continue
		}
		if grepFilter != "" {
			hay := strings.ToLower(entry.Summary + " " + entry.RunID)
			if !strings.Contains(hay, grepFilter) {
				continue
			}
		}
		if last > 0 && shown >= last {
			break
		}
		shown++
		if formatJSON {
			jsonOut = append(jsonOut, entry)
			continue
		}
		fmt.Printf(
			"[%s] %s | %s | findings: %d | %s\n",
			displayText(entry.Status),
			entry.Timestamp.Format("2006-01-02 15:04:05 UTC"),
			displayText(entry.RunID),
			entry.FindingCount,
			displayText(entry.Summary),
		)
	}
	if formatJSON {
		out, err := json.MarshalIndent(jsonOut, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
	} else if shown == 0 {
		fmt.Println("No history entries match the filters.")
	}

	return nil
}

func runRecoverHistoryCommand() error {
	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	repositoryRoot, err := git.RepositoryRoot(workingDir)
	if err != nil {
		return err
	}

	reportsDir := filepath.Join(repositoryRoot, ".m3tal-review", "reports")
	historyPath := filepath.Join(repositoryRoot, ".m3tal-review", "history.jsonl")
	if err := ensureReviewStorageSafe(repositoryRoot, reportsDir, historyPath); err != nil {
		return err
	}

	recovered, err := review.RecoverHistory(reportsDir, historyPath)
	if err != nil {
		return fmt.Errorf("recover history: %w", err)
	}

	if recovered == 0 {
		fmt.Println("No reports found to recover.")
		return nil
	}

	fmt.Printf("Successfully recovered %d review entries to history.\n", recovered)
	return nil
}
