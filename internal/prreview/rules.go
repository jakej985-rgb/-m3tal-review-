package prreview

import (
	"strings"
)

// RuleDoc describes the rationale and remediation for a deterministic review rule.
type RuleDoc struct {
	Name        string
	Category    string
	Severity    string
	Description string
	Example     string
	Rationale   string
	Remediation string
}

var catalog = map[string]RuleDoc{
	"pipe-to-shell": {
		Name:        "pipe-to-shell",
		Category:    "Security",
		Severity:    "Critical",
		Description: "Direct execution of arbitrary shell command strings via system shells (sh/bash/cmd/powershell).",
		Example:     `exec.Command("sh", "-c", userInput)`,
		Rationale:   "Passing unparsed or concatenated strings directly to shell interpreters enables command injection and arbitrary code execution.",
		Remediation: "Invoke specific binary paths directly with explicit argument slices without passing through a shell interpreter.",
	},
	"code-slop": {
		Name:        "code-slop",
		Category:    "Maintainability",
		Severity:    "Low",
		Description: "Code-quality heuristics: redundant boolean comparisons, empty blocks, deep nesting, and unreachable code.",
		Example:     `if isValid == true { ... }`,
		Rationale:   "Redundant comparisons and structural slop reduce code readability and increase cognitive overhead.",
		Remediation: "Simplify conditional statements directly: `if isValid { ... }`.",
	},
	"sql-injection": {
		Name:        "sql-injection",
		Category:    "Security",
		Severity:    "Critical",
		Description: "String-built SQL queries via formatting or concatenation.",
		Example:     `fmt.Sprintf("SELECT * FROM users WHERE id=%s", id)`,
		Rationale:   "Unparameterized queries allow attackers to manipulate SQL semantics and extract or corrupt database records.",
		Remediation: "Use parameterized queries with placeholder arguments: `db.Query(\"SELECT * FROM users WHERE id=$1\", id)`.",
	},
	"exposed-secret": {
		Name:        "exposed-secret",
		Category:    "Security",
		Severity:    "Critical",
		Description: "Hardcoded secret, private key, or provider API token committed in source.",
		Example:     `const apiKey = "AKIAIOSFODNN7EXAMPLE"`,
		Rationale:   "Committed credentials can be harvested from version control history and abused by unauthorized parties.",
		Remediation: "Rotate the exposed credential immediately and load secrets at runtime from environment variables or a secrets manager.",
	},
	"insecure-permissions": {
		Name:        "insecure-permissions",
		Category:    "Security",
		Severity:    "High",
		Description: "Files or directories created with world-writable permissions (0777 or 0666).",
		Example:     `os.Chmod("config.json", 0777)`,
		Rationale:   "World-writable files allow unprivileged local processes to modify application state and achieve local privilege escalation.",
		Remediation: "Restrict file permissions to owner-only or group-restricted modes such as 0600 or 0640.",
	},
	"debug-leftover": {
		Name:        "debug-leftover",
		Category:    "Quality",
		Severity:    "Medium",
		Description: "Debug statements or breakpoints left in production code paths.",
		Example:     `fmt.Println("DEBUG: token is", token)`,
		Rationale:   "Debug statements can leak sensitive variables into production logs and clutter standard output.",
		Remediation: "Remove debug statements or use leveled, structured logging with appropriate redaction.",
	},
	"trailing-whitespace": {
		Name:        "trailing-whitespace",
		Category:    "Style",
		Severity:    "Low",
		Description: "Trailing whitespace at the end of lines.",
		Example:     `func Hello() {    `,
		Rationale:   "Trailing whitespace causes noisy git diffs and violates standard formatting guidelines.",
		Remediation: "Strip trailing spaces from all modified lines.",
	},
}

// LookupRule retrieves rule documentation by rule name.
func LookupRule(name string) *RuleDoc {
	norm := strings.ToLower(strings.TrimSpace(name))
	if doc, ok := catalog[norm]; ok {
		return &doc
	}
	return nil
}
