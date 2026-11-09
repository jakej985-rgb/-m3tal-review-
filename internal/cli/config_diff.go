package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func runConfigCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: m3tal-review config diff [proposed-file] [--format json|text]")
	}

	subcommand := args[0]
	subArgs := args[1:]

	switch subcommand {
	case "diff":
		return runPolicyDiffCommand(subArgs)
	case "-h", "--help":
		fmt.Println("Usage: m3tal-review config diff [proposed-file] [--format json|text]")
		fmt.Println("Validate proposed policy and display effective configuration differences.")
		return nil
	default:
		return fmt.Errorf("unknown config subcommand %q; expected diff", subcommand)
	}
}

func runPolicyCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: m3tal-review policy diff|dry-run [proposed-file] [--format json|text]")
	}

	subcommand := args[0]
	subArgs := args[1:]

	switch subcommand {
	case "diff", "dry-run":
		return runPolicyDiffCommand(subArgs)
	case "-h", "--help":
		fmt.Println("Usage: m3tal-review policy diff|dry-run [proposed-file] [--format json|text]")
		fmt.Println("Validate proposed policy and display effective configuration differences without analysis.")
		return nil
	default:
		return fmt.Errorf("unknown policy subcommand %q; expected diff or dry-run", subcommand)
	}
}

func runPolicyDiffCommand(args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	repositoryRoot, err := git.RepositoryRoot(workingDir)
	if err != nil {
		// If outside git repo, allow diffing if explicit files are provided
		repositoryRoot = workingDir
	}

	var proposedPath string
	var basePath string
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
		case arg == "--proposed":
			if i+1 >= len(args) {
				return fmt.Errorf("option --proposed requires a file path")
			}
			i++
			proposedPath = args[i]
		case arg == "--base":
			if i+1 >= len(args) {
				return fmt.Errorf("option --base requires a file path")
			}
			i++
			basePath = args[i]
		case arg == "--dry-run":
			// Dry-run mode is default for diff (it never mutates files)
		case arg == "-h" || arg == "--help":
			fmt.Println("Usage: m3tal-review config diff [proposed-file] [--base <path>] [--format json|text]")
			fmt.Println("Validate proposed policy and display effective configuration differences.")
			return nil
		case len(arg) > 0 && arg[0] == '-':
			return fmt.Errorf("unknown option %q", arg)
		default:
			if proposedPath == "" {
				proposedPath = arg
			} else {
				return fmt.Errorf("unexpected argument %q; expected single proposed policy file", arg)
			}
		}
	}

	defaultPolicyFile := filepath.Join(repositoryRoot, ".m3tal-review-policy.json")

	// If no base specified, use repository's existing .m3tal-review-policy.json
	if basePath == "" {
		basePath = defaultPolicyFile
	}

	// If no proposed specified, compare default policy against git staged/committed
	var basePolicy, proposedPolicy review.ReviewPolicy
	var propValidationErrors []string

	if proposedPath == "" {
		// Compare committed/staged policy vs working tree policy
		proposedPath = defaultPolicyFile
		// Read base from git staged/HEAD
		stagedData, gitErr := git.StagedFileContent(repositoryRoot, ".m3tal-review-policy.json")
		if gitErr == nil && len(stagedData) > 0 {
			basePolicy, _, _ = review.ParseReviewPolicy(stagedData)
		}

		var propErr error
		proposedPolicy, propValidationErrors, propErr = review.ReadReviewPolicyFile(proposedPath)
		if propErr != nil {
			return fmt.Errorf("failed to read proposed policy %s: %w", proposedPath, propErr)
		}
	} else {
		// Explicit proposed file provided
		var baseErr error
		basePolicy, _, baseErr = review.ReadReviewPolicyFile(basePath)
		if baseErr != nil && !os.IsNotExist(baseErr) {
			return fmt.Errorf("failed to read base policy %s: %w", basePath, baseErr)
		}

		var propErr error
		proposedPolicy, propValidationErrors, propErr = review.ReadReviewPolicyFile(proposedPath)
		if propErr != nil {
			return fmt.Errorf("failed to read proposed policy %s: %w", proposedPath, propErr)
		}
	}

	diffResult := review.DiffPolicies(basePolicy, proposedPolicy)
	diffResult.BasePath = basePath
	diffResult.ProposedPath = proposedPath
	diffResult.ValidationErrors = propValidationErrors
	diffResult.Valid = (len(propValidationErrors) == 0)

	if format == "json" {
		data, err := json.MarshalIndent(diffResult, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal policy diff json: %w", err)
		}
		fmt.Println(string(data))
		if !diffResult.Valid {
			return fmt.Errorf("proposed policy validation failed")
		}
		return nil
	}

	// Human-readable text format
	if !diffResult.Valid {
		fmt.Printf("Proposed Policy Validation FAILED (%s):\n", displayText(proposedPath))
		for _, errStr := range propValidationErrors {
			fmt.Printf("  ! %s\n", displayText(errStr))
		}
		return fmt.Errorf("proposed policy validation failed: %d errors", len(propValidationErrors))
	}

	fmt.Printf("Policy Diff (%s vs %s):\n", displayText(basePath), displayText(proposedPath))
	formatted := review.FormatPolicyDiff(diffResult)
	fmt.Print(formatted)

	return nil
}
