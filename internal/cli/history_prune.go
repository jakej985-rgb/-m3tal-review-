package cli

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func commandHistoryPrune(repositoryRoot string, args []string) error {
	var opts review.PruneOptions
	format := "text"

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--dry-run":
			opts.DryRun = true
		case "--format":
			if i+1 >= len(args) {
				return fmt.Errorf("option --format requires a value (json|text)")
			}
			i++
			format = args[i]
		case "--format=json":
			format = "json"
		case "--format=text":
			format = "text"
		case "--older-than":
			if i+1 >= len(args) {
				return fmt.Errorf("option --older-than requires a duration value (e.g. 30d, 24h, 1w)")
			}
			i++
			d, err := review.ParseRetentionDuration(args[i])
			if err != nil {
				return err
			}
			opts.OlderThan = &d
		case "--keep":
			if i+1 >= len(args) {
				return fmt.Errorf("option --keep requires a count value")
			}
			i++
			count, err := strconv.Atoi(args[i])
			if err != nil || count < 0 {
				return fmt.Errorf("invalid --keep count %q", args[i])
			}
			opts.Keep = &count
		case "--max-size":
			if i+1 >= len(args) {
				return fmt.Errorf("option --max-size requires a size value (e.g. 10MB, 500KB)")
			}
			i++
			sz, err := review.ParseRetentionSize(args[i])
			if err != nil {
				return err
			}
			opts.MaxSize = &sz
		case "-h", "--help":
			fmt.Println("Usage: m3tal-review history prune [--older-than <duration>] [--keep <count>] [--max-size <bytes/mb>] [--dry-run] [--format json|text]")
			fmt.Println("Prune historical reports and history entries deterministically and safely.")
			return nil
		default:
			return fmt.Errorf("unknown history prune option %q", arg)
		}
	}

	if opts.OlderThan == nil && opts.Keep == nil && opts.MaxSize == nil {
		return fmt.Errorf("at least one retention option (--older-than, --keep, --max-size) is required")
	}

	reportsDir := filepath.Join(repositoryRoot, ".m3tal-review", "reports")
	historyPath := filepath.Join(repositoryRoot, ".m3tal-review", "history.jsonl")
	if err := ensureReviewStorageSafe(repositoryRoot, reportsDir, historyPath); err != nil {
		return err
	}

	result, err := review.PruneHistory(repositoryRoot, opts)
	if err != nil {
		return err
	}

	if format == "json" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal prune result json: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	statusPrefix := ""
	if result.DryRun {
		statusPrefix = " [DRY RUN]"
	}

	fmt.Printf("History Prune%s:\n", statusPrefix)
	fmt.Printf("  Initial entries:  %d\n", result.InitialEntries)
	fmt.Printf("  Retained entries: %d\n", result.RetainedEntries)
	fmt.Printf("  Pruned entries:   %d\n", result.PrunedEntries)
	fmt.Printf("  Deleted reports:  %d\n", result.DeletedReports)
	fmt.Printf("  Reclaimed space:  %d bytes\n", result.BytesReclaimed)

	if len(result.Pruned) > 0 {
		fmt.Println("\nPruned runs:")
		for _, item := range result.Pruned {
			fmt.Printf("  - %s (%s, %d bytes): %s\n",
				displayText(item.RunID),
				item.Timestamp.Format("2006-01-02 15:04:05"),
				item.SizeBytes,
				displayText(item.Reason),
			)
		}
	}

	return nil
}
