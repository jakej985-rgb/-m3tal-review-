package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// commandWatch re-runs the staged review whenever the staged diff changes.
func commandWatch(interval time.Duration) error {
	if interval <= 0 {
		interval = 3 * time.Second
	}
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
				findings := review.NewEngine(defaultRules(repositoryRoot)...).RunContext(ctx, diff)
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
