package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
)

type ruleDoc struct {
	Name        string
	Description string
	Example     string
}

var ruleCatalog = []ruleDoc{
	{"code-slop", "Code-quality heuristics: redundant boolean comparisons, empty blocks, deep nesting, else-after-return, unreachable code, long functions, mutable defaults, duplicated blocks, lint suppressions, and more (see README for the full per-language list).", "if x == true { ... }"},
	{"todo-leftover", "TODO/FIXME/XXX markers in comments and Markdown task headings.", "// TODO: handle this"},
	{"debug-leftover", "Likely debug output: fmt.Print*, console.log, println, debugger, breakpoint, etc.", "fmt.Println(\"debug\")"},
	{"hardcoded-credential", "Credential-looking name/value assignments in source.", "password = \"hunter2\""},
	{"exposed-secret", "High-confidence secret formats: PEM private keys and provider tokens (AWS, GitHub, GitLab, Slack, OpenAI, Stripe, Google, npm).", "AKIA..."},
	{"path-traversal", "File APIs fed by request input or os.Args without sanitization.", "os.Open(r.URL.Path)"},
	{"weak-cryptography", "MD5/SHA-1/DES/RC4 for security purposes; math/rand/random/Math.random for token-like values.", "md5.Sum(data)"},
	{"unsafe-deserialization", "pickle/marshal/yaml.load/unserialize/node-serialize of untrusted data.", "pickle.loads(blob)"},
	{"dangerous-eval", "eval/exec/new Function/string setTimeout/assert-style dynamic execution.", "eval(userInput)"},
	{"cross-site-scripting", "innerHTML/outerHTML/document.write/dangerouslySetInnerHTML and template bindings that render raw HTML.", "el.innerHTML = data"},
	{"sql-injection", "String-built SQL queries via fmt.Sprintf/concat/f-strings/template literals.", "fmt.Sprintf(\"SELECT * FROM u WHERE id=%s\", id)"},
	{"insecure-tls-verification", "TLS certificate verification disabled (InsecureSkipVerify, VERIFY_NONE, NODE_TLS_REJECT_UNAUTHORIZED=0).", "InsecureSkipVerify: true"},
	{"risky-shell-execution", "Shell command execution with interpolated input.", "exec.Command(\"sh\", \"-c\", cmd)"},
	{"world-writable-file-mode", "Files created with world-writable permissions (0777/0666).", "os.Chmod(f, 0777)"},
	{"review-risk", "Changed paths matching configured high-risk globs in .m3tal-review-policy.json.", "risk_paths: [\"internal/auth/**\"]"},
	{"review-policy", "Policy violations: forbidden paths and missing coupled changes.", "forbidden_paths: [\"secrets/**\"]"},
	{"review-policy-config-error", "The .m3tal-review-policy.json file could not be loaded.", "invalid JSON"},
	{"code-slop-analysis-error", "A staged file could not be parsed for syntax-aware analysis.", "unbalanced braces"},
	{"repository-lint", "Repository lint command (gofmt/go vet/custom) reported issues.", "gofmt -l ."},
	{"confidence-*", "Confidence checks (gofmt, go vet, go test, optional scanners) failed.", "go test ./..."},
}

func listRules() error {
	fmt.Println("M3TAL Review rules")
	for _, rule := range ruleCatalog {
		fmt.Printf("  %-32s %s\n", rule.Name, rule.Description)
	}
	fmt.Println()
	fmt.Println("The code-slop rule covers many per-language checks; see README \"Slop Analyzer Coverage\" for details.")
	return nil
}

func explainRule(name string) error {
	for _, rule := range ruleCatalog {
		if rule.Name == name {
			fmt.Println(rule.Name)
			fmt.Println("  ", rule.Description)
			fmt.Println("   Example:", rule.Example)
			return nil
		}
	}
	return fmt.Errorf("unknown rule %q; run 'm3tal-review list-rules' to see available rules", name)
}

func installHook(force bool) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}
	if err := git.Available(); err != nil {
		return err
	}
	repositoryRoot, err := git.RepositoryRoot(workingDir)
	if err != nil {
		return err
	}
	hooksDir, err := gitHooksPath(repositoryRoot)
	if err != nil {
		return err
	}
	hookPath := filepath.Join(hooksDir, "pre-commit")
	content := "#!/bin/sh\n# Installed by m3tal-review\nm3tal-review review\n"
	if existing, err := os.ReadFile(hookPath); err == nil {
		if strings.Contains(string(existing), "m3tal-review") && !force {
			return fmt.Errorf("pre-commit hook already contains m3tal-review; use --force to replace it")
		}
		if !force {
			return fmt.Errorf("pre-commit hook already exists at %s; use --force to overwrite", displayText(hookPath))
		}
	}
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("create hooks directory: %w", err)
	}
	if err := os.WriteFile(hookPath, []byte(content), 0755); err != nil {
		return fmt.Errorf("write pre-commit hook: %w", err)
	}
	fmt.Println("Installed pre-commit hook:", displayText(hookPath))
	return nil
}

// gitHooksPath resolves the hooks directory via git rev-parse.
func gitHooksPath(repositoryRoot string) (string, error) {
	// "git rev-parse --git-path hooks" handles worktrees and custom git dirs.
	output, err := runCommand(context.Background(), repositoryRoot, "git", "-c", "core.fsmonitor=false", "rev-parse", "--git-path", "hooks")
	if err != nil {
		return "", fmt.Errorf("resolve git hooks path: %w", err)
	}
	hooks := strings.TrimSpace(string(output))
	if !filepath.IsAbs(hooks) {
		hooks = filepath.Join(repositoryRoot, hooks)
	}
	return hooks, nil
}
