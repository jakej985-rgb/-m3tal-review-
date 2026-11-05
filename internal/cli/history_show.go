package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// commandHistoryShow prints the full stored report for a run ID, including
// findings and the new/resolved delta computed against the previous run.
func commandHistoryShow(repositoryRoot, runID string) error {
	if runID == "" || strings.ContainsAny(runID, `/\`) || runID == "." || runID == ".." {
		return fmt.Errorf("invalid run ID %q", runID)
	}
	reportsDir := filepath.Join(repositoryRoot, ".m3tal-review", "reports")
	info, err := os.Lstat(reportsDir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("no reports directory; nothing to show")
	}

	path := filepath.Join(reportsDir, runID+".json")
	if _, err := os.Lstat(path); err != nil {
		// Prefix match on run IDs for convenience.
		entries, readErr := os.ReadDir(reportsDir)
		if readErr != nil {
			return fmt.Errorf("read reports: %w", readErr)
		}
		var matches []string
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), runID) && strings.HasSuffix(e.Name(), ".json") {
				matches = append(matches, e.Name())
			}
		}
		if len(matches) == 0 {
			return fmt.Errorf("no report found for run ID %q", runID)
		}
		if len(matches) > 1 {
			sort.Strings(matches)
			return fmt.Errorf("run ID %q is ambiguous (%d matches); be more specific", runID, len(matches))
		}
		path = filepath.Join(reportsDir, matches[0])
	}

	report, err := review.ReadReport(path)
	if err != nil {
		return err
	}

	fmt.Printf("Run %s\n", displayText(report.RunID))
	fmt.Printf("  timestamp:  %s\n", report.Timestamp.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("  scope:      %s\n", displayText(report.Scope))
	fmt.Printf("  branch:     %s @ %s\n", displayText(report.Branch), displayText(report.CommitSHA))
	fmt.Printf("  tool:       %s\n", displayText(report.ToolVersion))
	fmt.Printf("  passed:     %t\n", report.Passed)
	if report.Summary != "" {
		fmt.Printf("  summary:    %s\n", displayText(report.Summary))
	}
	fmt.Printf("  files:      %d reviewed", len(report.ReviewedFiles))
	if len(report.UnanalyzedFiles) > 0 {
		fmt.Printf(", %d unanalyzed", len(report.UnanalyzedFiles))
	}
	fmt.Println()

	if report.FindingChanges != nil {
		fmt.Printf("  delta:      %d new, %d resolved, %d existing\n",
			len(report.FindingChanges.New), len(report.FindingChanges.Resolved), report.FindingChanges.Existing)
		for _, fp := range report.FindingChanges.New {
			fmt.Printf("    + %s\n", displayText(fp))
		}
		for _, fp := range report.FindingChanges.Resolved {
			fmt.Printf("    - %s\n", displayText(fp))
		}
	}

	for _, f := range report.Findings {
		loc := displayText(f.File)
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.Line)
		}
		fmt.Printf("[%s] %s: %s (%s)\n", displayText(f.Severity), loc, displayText(f.Message), displayText(f.Rule))
	}
	if len(report.Findings) == 0 {
		fmt.Println("No findings.")
	}
	return nil
}
