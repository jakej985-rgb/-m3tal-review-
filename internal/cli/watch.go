package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// parseWatchOptions accepts --jobs N (or --jobs=N) and rejects anything else.
func parseWatchOptions(args []string) (int, error) {
	jobs := 0
	for i := 0; i < len(args); i++ {
		arg := args[i]
		value := ""
		hasValue := false
		if rest, ok := strings.CutPrefix(arg, "--jobs="); ok {
			value, hasValue = rest, true
			arg = "--jobs"
		}
		switch arg {
		case "--jobs":
			if !hasValue {
				if i+1 >= len(args) {
					return 0, fmt.Errorf("--jobs requires a non-negative integer")
				}
				i++
				value = args[i]
			}
			n, err := parseJobsValue(value)
			if err != nil {
				return 0, err
			}
			jobs = n
		default:
			return 0, fmt.Errorf("unknown watch option %q", arg)
		}
	}
	return jobs, nil
}

// commandWatch re-runs the staged review whenever the staged diff changes.
func commandWatch(interval time.Duration, args []string) error {
	if interval <= 0 {
		interval = 3 * time.Second
	}
	jobs, err := parseWatchOptions(args)
	if err != nil {
		return err
	}
	capProcessCPU(jobs)
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	if err := git.Available(); err != nil {
		return err
	}
	repositoryRoot, err := git.RepositoryRoot(workingDir)
	if err != nil {
		return err
	}

	// SIGINT/SIGTERM cancels the context, which also interrupts an
	// in-flight review instead of only being noticed between iterations.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var lastHash string
	for {
		diff, err := git.StagedDiff(repositoryRoot)
		if err != nil {
			// Transient failures (e.g. index.lock during a concurrent
			// git operation) must not kill the watch loop.
			fmt.Fprintf(os.Stderr, "watch: staged diff failed: %v\n", err)
		} else if diff == "" {
			// Reset so re-staging identical content re-reports.
			lastHash = ""
		} else {
			sum := sha256.Sum256([]byte(diff))
			hash := hex.EncodeToString(sum[:])
			if hash != lastHash {
				lastHash = hash
				fmt.Printf("=== %s — %d bytes staged ===\n", time.Now().Format("15:04:05"), len(diff))
				findings := cappedEngine(jobs, defaultRules(repositoryRoot)...).RunContext(ctx, diff)
				if ctx.Err() != nil {
					fmt.Println("\nWatch stopped.")
					return nil
				}
				findings = review.ApplyFindingFilters(diff, findings, repositoryRoot, false)
				if len(findings) == 0 {
					fmt.Println("No findings.")
				}
				for _, f := range findings {
					loc := f.File
					if f.Line > 0 {
						loc = fmt.Sprintf("%s:%d", loc, f.Line)
					}
					fmt.Printf("[%s] %s: %s (%s)\n", f.Severity, loc, f.Message, f.Rule)
				}
			}
		}
		select {
		case <-ctx.Done():
			fmt.Println("\nWatch stopped.")
			return nil
		case <-time.After(interval):
		}
	}
}
