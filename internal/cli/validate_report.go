package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func runValidateReport(args []string) error {
	var targetPath string
	format := "text"

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--format":
			if i+1 >= len(args) {
				return fmt.Errorf("option --format requires a value (json|text)")
			}
			i++
			format = args[i]
		case arg == "--format=json":
			format = "json"
		case arg == "--format=text":
			format = "text"
		case arg == "-h" || arg == "--help":
			fmt.Println("Usage: m3tal-review validate-report <path> [--format json|text]")
			fmt.Println("Validate single report file or report directory against schema and integrity rules.")
			return nil
		case len(arg) > 0 && arg[0] == '-':
			return fmt.Errorf("unknown option %q", arg)
		default:
			if targetPath == "" {
				targetPath = arg
			} else {
				return fmt.Errorf("unexpected argument %q; expected single path", arg)
			}
		}
	}

	if targetPath == "" {
		return fmt.Errorf("usage: m3tal-review validate-report <path> [--format json|text]")
	}

	summary := review.ValidateReportTarget(targetPath)

	if format == "json" {
		data, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal validation json: %w", err)
		}
		fmt.Println(string(data))
		if !summary.Valid {
			return fmt.Errorf("report validation failed: %d invalid report(s)", summary.InvalidReports)
		}
		return nil
	}

	// Human-readable text format
	fmt.Printf("M3TAL Report Validation: %s\n", displayText(targetPath))
	for _, res := range summary.Results {
		if res.Valid {
			fmt.Printf("  PASS: %s (run_id: %s, findings: %d, checks: %d)\n",
				displayText(res.Path),
				displayText(res.RunID),
				res.FindingCount,
				res.CheckCount,
			)
		} else {
			fmt.Printf("  FAIL: %s (run_id: %s)\n",
				displayText(res.Path),
				displayText(res.RunID),
			)
			for _, errItem := range res.Errors {
				fmt.Printf("    - [%s] %s\n", displayText(errItem.Field), displayText(errItem.Message))
			}
		}
	}

	fmt.Println()
	if summary.Valid {
		fmt.Printf("Summary: %d report(s) validated successfully.\n", summary.TotalReports)
		return nil
	}

	fmt.Fprintf(os.Stderr, "Summary: %d of %d report(s) failed validation.\n", summary.InvalidReports, summary.TotalReports)
	return fmt.Errorf("report validation failed: %d invalid report(s)", summary.InvalidReports)
}
