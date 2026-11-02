# m3tal-review

`m3tal-review` is a determinisic, local code-review CLI tool for the m3tal app ecosystem. It helps review code for maintainability (slop) and security issues.

It provides actionable findings, records review trails (history), and supports a manual fix-and-re-review workflow (automated repair tracking is not currently supported).

## Features

- **Review Engine**: Runs deterministic checks on staged Git changes.
- **Remediation Guidance**: Every finding provides actionable steps to fix the issue.
- **Slop Detector**: Automatically detects unidiomatic code, redundant boolean comparisons (`== true`), excessive nesting, and empty blocks to help keep your codebase clean and maintainable.
- **Security Checks**: Detects hardcoded credentials, world-writable file permissions (0777), disabled TLS verification, and risky shell executions.
- **Code Quality**: Identifies leftover `TODO` markers, debug print statements, and runs `gofmt` and `go vet` to enforce formatting and find subtle bugs.
- **Review History**: Maintains a JSONL log of previous reviews.
- **Detailed Reports**: Saves full review results as JSON files.

## Installation

Ensure you have Go 1.23+ installed.

```bash
go build -o m3tal-review ./cmd/m3tal-review
```

Move the binary to a directory in your `PATH` (e.g., `/usr/local/bin`).

## Usage

Run the CLI inside a Git repository.

### Check Status

View the current repository state, branch, and staged files:

```bash
m3tal-review check
```

### Run a Review

Review currently **staged** changes. This will generate a run ID, create a report, and log it to history.

```bash
m3tal-review review
```

If issues are found, the command will exit with a non-zero status and print the findings with their line numbers and remediation guidance.

To address findings:
1. Manually fix the issues in your code based on the remediation guidance.
2. Stage your changes (`git add`).
3. Run `m3tal-review review` again to verify the fixes.

### View History

List past reviews and their summaries:

```bash
m3tal-review history
```

### View a Specific Report

Retrieve the full details and findings of a past review using its Run ID:

```bash
m3tal-review show <run-id>
```

### Linting

Run standard Go formatting and vet checks across the repository:

```bash
m3tal-review lint
```

## Interpreting Findings

Findings include:
- **Severity**: `low`, `medium`, or `high`.
- **File/Line**: Where the issue occurred.
- **Message**: A description of the problem.
- **Remediation**: Actionable advice on how to resolve the issue.

Example finding:
```
[high] main.go:42: Possible hardcoded credential assigned to password (hardcoded-credential)
  Remediation: Remove hardcoded credentials. Use environment variables or a secret management system.
```
