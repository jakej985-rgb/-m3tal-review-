package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// runDiffReview reviews an arbitrary unified diff (from a file or stdin)
// against the current repository's rules.
func runDiffReview(diff string, sourceName string) error {
	if strings.TrimSpace(diff) == "" {
		return fmt.Errorf("no diff content provided")
	}
	if len(diff) > 64<<20 {
		return fmt.Errorf("diff exceeds 64 MiB limit")
	}
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	repositoryRoot := ""
	if root, err := git.RepositoryRoot(workingDir); err == nil {
		repositoryRoot = root
	}
	findings := review.NewEngine(defaultRules(repositoryRoot)...).Run(diff)
	findings = review.ApplyFindingFilters(diff, findings, repositoryRoot, false)
	if len(findings) == 0 {
		fmt.Println("No findings.")
		return nil
	}
	for _, f := range findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.Line)
		}
		fmt.Printf("[%s] %s: %s (%s)\n", f.Severity, loc, f.Message, f.Rule)
	}
	fmt.Printf("%d finding(s) from %s\n", len(findings), sourceName)
	return nil
}

func commandStdin() error {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<20))
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	return runDiffReview(string(data), "stdin")
}

func commandDiff(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: m3tal-review diff <file.diff|file.patch>")
	}
	path := args[0]
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat diff file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("diff file must be a regular file, not a symlink")
	}
	if info.Size() > 64<<20 {
		return fmt.Errorf("diff file exceeds 64 MiB limit")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read diff file: %w", err)
	}
	return runDiffReview(string(data), filepath.Base(path))
}

func commandDoctor() error {
	checks := []struct {
		name string
		ok   bool
		det  string
	}{}
	if err := git.Available(); err != nil {
		checks = append(checks, struct {
			name string
			ok   bool
			det  string
		}{"git", false, err.Error()})
	} else {
		checks = append(checks, struct {
			name string
			ok   bool
			det  string
		}{"git", true, "available"})
	}
	workingDir, _ := os.Getwd()
	if root, err := git.RepositoryRoot(workingDir); err != nil {
		checks = append(checks, struct {
			name string
			ok   bool
			det  string
		}{"git repository", false, err.Error()})
	} else {
		checks = append(checks, struct {
			name string
			ok   bool
			det  string
		}{"git repository", true, root})
	}
	if root, err := git.RepositoryRoot(workingDir); err == nil {
		storage := filepath.Join(root, ".m3tal-review")
		if err := os.MkdirAll(storage, 0o755); err != nil {
			checks = append(checks, struct {
				name string
				ok   bool
				det  string
			}{"storage writable", false, err.Error()})
		} else {
			probe := filepath.Join(storage, ".probe")
			if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
				checks = append(checks, struct {
					name string
					ok   bool
					det  string
				}{"storage writable", false, err.Error()})
			} else {
				_ = os.Remove(probe)
				checks = append(checks, struct {
					name string
					ok   bool
					det  string
				}{"storage writable", true, storage})
			}
		}
	}
	failed := false
	for _, c := range checks {
		status := "ok"
		if !c.ok {
			status = "FAIL"
			failed = true
		}
		fmt.Printf("%-18s %-4s %s\n", c.name, status, c.det)
	}
	if failed {
		return fmt.Errorf("doctor found problems")
	}
	fmt.Println("All checks passed.")
	_ = time.Now
	return nil
}
