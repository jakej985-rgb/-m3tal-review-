package cli

import (
	"fmt"
	"os"
	"strconv"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
)

func runLSPCommand() error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	repoRoot, _ := git.RepositoryRoot(workingDir)
	server := NewLSPServer(os.Stdin, os.Stdout, repoRoot)
	return server.Serve()
}

func runDashboardCommand(commandArgs []string) error {
	port := 8080
	for i := 0; i < len(commandArgs); i++ {
		if commandArgs[i] == "--port" && i+1 < len(commandArgs) {
			if p, err := strconv.Atoi(commandArgs[i+1]); err == nil && p > 0 {
				port = p
			}
			i++
		}
	}
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	repoRoot, err := git.RepositoryRoot(workingDir)
	if err != nil {
		repoRoot = workingDir
	}
	return StartDashboardServer(repoRoot, port)
}

func printHelp() {
	fmt.Println(appName)
	fmt.Println("Available commands:")
	fmt.Println("  version")
	fmt.Println("  check")
	fmt.Println("  review")
	fmt.Println("    --profile fast|full  Add local Go format, vet, and test checks in full mode")
	fmt.Println("    --with-tools        Run installed gitleaks, gosec, and osv-scanner binaries")
	fmt.Println("    --check-run        Post a GitHub Check Run with annotations")
	fmt.Println("    --pr-comment       Comment findings on the current PR via gh")
	fmt.Println("    --pr-mode          Delegate to Devin/CodeRabbit-style pure-code PR reviewer")
	fmt.Println("    --jobs N           Cap rules analysed at once (default: all CPU cores; 0 = auto)")
	fmt.Println("  pr-review           Devin/CodeRabbit-style pure-code AI-like PR reviewer")
	fmt.Println("    --base <ref>       Diff base ref (default: origin/main, HEAD~1)")
	fmt.Println("    --interactive, -i  Interactively review and apply suggested fixes")
	fmt.Println("    --post-gh          Submit PR review and inline comments to GitHub")
	fmt.Println("    --pr <number>      Target GitHub pull request number")
	fmt.Println("    --repo <owner/repo> Target GitHub repository")
	fmt.Println("    --comment-only     Post review comments without blocking quality gate")
	fmt.Println("    --output <file>    Save generated review markdown to file")
	fmt.Println("  install-github-workflow [--force] Install GitHub Actions PR review workflow")
	fmt.Println("  check-deps [path]   Analyze Go module hygiene and license policy")
	fmt.Println("    --format text|json|jsonl")
	fmt.Println("    --strict          Fail on any hygiene or license finding")
	fmt.Println("    --allow-licenses  Allowlist of approved SPDX licenses")
	fmt.Println("    --deny-licenses   Denylist of forbidden SPDX licenses")
	fmt.Println("    --allow-unknown   Permit unknown/missing dependency licenses")
	fmt.Println("    --jobs N           Cap analysis at once (default: all CPU cores; 0 = auto)")
	fmt.Println("  audit")
	fmt.Println("    --profile fast|full  Add local Go format, vet, and test checks in full mode")
	fmt.Println("    --with-tools        Run installed gitleaks, gosec, and osv-scanner binaries")
	fmt.Println("    --with-slop         Include code-slop findings (skipped by default in audit)")
	fmt.Println("    --vuln-scan        Query OSV for known CVEs in manifests (network)")
	fmt.Println("    --check-deps       Run Go module hygiene and license policy checks")
	fmt.Println("    --include-ignored  Include ignored untracked files (bounded by scan limits)")
	fmt.Println("    --max-files N      Set the maximum files to read (default 10000)")
	fmt.Println("    --max-bytes N      Set the maximum total bytes to read (default 134217728)")
	fmt.Println("    --jobs N           Cap rules analysed at once (default: all CPU cores; 0 = auto)")
	fmt.Println("  history [--last N] [--status S] [--scope S] [--grep text] [--format json]")
	fmt.Println("  history show <run-id> [--format json|jsonl|html]")
	fmt.Println("  history prune [--older-than <duration>] [--keep <count>] [--max-size <bytes/mb>] [--dry-run]")
	fmt.Println("  validate-report <path> [--format json|text]")
	fmt.Println("  suppressions audit [--actor <name>] [--rule <rule>] [--file <path>] [--verify]")
	fmt.Println("  config diff [proposed-file] [--base <path>] [--format json|text]")
	fmt.Println("  policy diff|dry-run [proposed-file] [--format json|text]")
	fmt.Println("  show <run-id>")
	fmt.Println("  diff [--jobs N] <file.patch>  Review an arbitrary patch file")
	fmt.Println("  stdin [--jobs N]    Review a diff from stdin")
	fmt.Println("  watch [--jobs N]    Re-review when the staged diff changes")
	fmt.Println("  doctor              Check git/repo/storage health")
	fmt.Println("  list-rules          List all registered rules")
	fmt.Println("  explain <rule>      Explain a rule with an example")
	fmt.Println("  install-hook [--force]  Install a pre-commit hook")
	fmt.Println("  completions <bash|zsh|fish>")
	fmt.Println("  lint [--jobs N]     Run gofmt and go vet across the repository")
	fmt.Println("  recover-history")
	fmt.Println("  repair [run-id]     Constrained isolated repair workflow")
	fmt.Println("    --finding <id>     Repair specific finding ID")
	fmt.Println("    --rule <rule>      Repair findings from specific rule")
	fmt.Println("    --fixer <name>     Use specific allowlisted fixer")
	fmt.Println("    --max-attempts N   Maximum repair attempts (default 3)")
	fmt.Println("    --jobs N           Cap rules analysed at once (default: all CPU cores; 0 = auto)")
	fmt.Println("    --dry-run          Simulate and verify in sandbox without applying")
	fmt.Println("    --yes, --approve   Approve verified repairs without prompt")
	fmt.Println("    --history          Display repair audit history")
	fmt.Println("  lsp                 Run Language Server Protocol daemon on stdin/stdout")
	fmt.Println("  dashboard [--port N] Launch local browser review dashboard and trends")
	fmt.Println("  version [--json]")
	fmt.Println("  help")
}
