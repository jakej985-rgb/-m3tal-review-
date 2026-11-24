package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

var (
	appName = "M3TAL Review"
	version = "1.1.0"
)

func Run(args []string) error {
	command := "help"
	commandArgs := []string{}

	if len(args) > 0 {
		command = args[0]
		commandArgs = args[1:]
	}

	switch command {
	case "-h", "--help", "-help":
		command = "help"
	case "-v", "--version", "-version":
		command = "version"
	}

	if command == "show" {
		if len(args) < 2 {
			return fmt.Errorf("usage: m3tal-review show <run-id>")
		}

		return outputSafeError(showReport(args[1]))
	}

	return outputSafeError(executeWithArgs(command, commandArgs))
}

type safeOutputError struct {
	err error
}

func (e safeOutputError) Error() string { return displayText(e.err.Error()) }
func (e safeOutputError) Unwrap() error { return e.err }

func outputSafeError(err error) error {
	if err == nil {
		return nil
	}
	return safeOutputError{err: err}
}

func execute(command string, args ...string) error {
	return executeWithArgs(command, args)
}

func executeWithArgs(command string, commandArgs []string) error {
	switch command {
	case "version":
		if len(commandArgs) > 0 && commandArgs[0] == "--json" {
			fmt.Printf("{\"name\":\"%s\",\"version\":\"%s\",\"go\":\"%s\"}\n", appName, version, runtime.Version())
			return nil
		}
		fmt.Println(appName)
		fmt.Println("Version:", version)
		fmt.Println("Go:", runtime.Version())

		return nil

	case "list-rules":
		return listRules()

	case "explain":
		if len(commandArgs) != 1 {
			return fmt.Errorf("usage: m3tal-review explain <rule>")
		}
		return explainRule(commandArgs[0])

	case "stdin":
		return commandStdin(commandArgs)

	case "diff":
		return commandDiff(commandArgs)

	case "doctor":
		return commandDoctor()

	case "watch":
		return commandWatch(3*time.Second, commandArgs)

	case "completions":
		if len(commandArgs) != 1 {
			return fmt.Errorf("usage: m3tal-review completions <bash|zsh|fish>")
		}
		return commandCompletions(commandArgs[0])

	case "install-hook":
		force := len(commandArgs) > 0 && commandArgs[0] == "--force"
		return installHook(force)

	case "install-github-workflow", "install-workflow":
		return runInstallWorkflow(commandArgs)

	case "pr-review":
		return runPRReview(commandArgs)

	case "check-deps":
		return commandCheckDeps(commandArgs)

	case "check":
		return runCheckCommand()

	case "review":
		return runReviewCommand(commandArgs)

	case "audit":
		return runAuditCommand(commandArgs)

	case "history":
		return runHistoryCommand(commandArgs)

	case "lint":
		return commandLint(commandArgs)

	case "recover-history":
		return runRecoverHistoryCommand()

	case "repair":
		return commandRepair(commandArgs)

	case "validate-report":
		return runValidateReport(commandArgs)

	case "suppressions", "suppression":
		return runSuppressionsCommand(commandArgs)

	case "config":
		return runConfigCommand(commandArgs)

	case "policy":
		return runPolicyCommand(commandArgs)

	case "lsp":
		return runLSPCommand()

	case "dashboard":
		return runDashboardCommand(commandArgs)

	case "help":
		printHelp()
		return nil

	default:
		printHelp()
		return fmt.Errorf("unknown command %q", command)
	}
}

func printCheckResults(checks []review.CheckResult) {
	for _, check := range checks {
		fmt.Printf("Check [%s] %s", displayText(check.Status), displayText(check.Name))
		if check.Message != "" {
			fmt.Printf(": %s", displayText(check.Message))
		}
		fmt.Println()
	}
}

func printFindingChanges(changes *review.FindingChanges) {
	if changes != nil {
		fmt.Printf("Finding changes: %d new, %d resolved, %d unchanged\n", len(changes.New), len(changes.Resolved), changes.Existing)
	}
}

// ensureReviewStorageSafe rejects symlinks in repository-local report and
// history paths. The CLI processes untrusted repositories, so storage paths
// must not redirect writes or reads outside the repository.
func ensureReviewStorageSafe(repositoryRoot string, paths ...string) error {
	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	for _, target := range paths {
		absTarget, err := filepath.Abs(target)
		if err != nil {
			return fmt.Errorf("resolve review storage path: %w", err)
		}
		rel, err := filepath.Rel(root, absTarget)
		if err != nil || !filepath.IsLocal(rel) {
			return fmt.Errorf("review storage path is outside the repository: %s", displayText(target))
		}
		current := root
		parts := strings.Split(rel, string(filepath.Separator))
		for i, part := range parts {
			current = filepath.Join(current, part)
			info, err := os.Lstat(current)
			if os.IsNotExist(err) {
				break
			}
			if err != nil {
				return fmt.Errorf("inspect review storage path %s: %w", displayText(current), err)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing symlink in review storage path: %s", displayText(current))
			}
			if i < len(parts)-1 && !info.IsDir() {
				return fmt.Errorf("review storage path component is not a directory: %s", displayText(current))
			}
		}
	}
	return nil
}

func displayText(value string) string {
	var displayed strings.Builder
	for _, r := range value {
		if !unicode.IsControl(r) {
			displayed.WriteRune(r)
			continue
		}
		switch {
		case r <= 0xff:
			fmt.Fprintf(&displayed, "\\x%02x", r)
		case r <= 0xffff:
			fmt.Fprintf(&displayed, "\\u%04x", r)
		default:
			fmt.Fprintf(&displayed, "\\U%08x", r)
		}
	}
	return displayed.String()
}
