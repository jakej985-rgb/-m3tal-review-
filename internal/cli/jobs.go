package cli

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// parseJobsValue validates a --jobs argument. Every command that accepts the
// flag shares this rule so they cannot drift: any non-negative integer is
// valid, and 0 (like an unset flag) means auto.
func parseJobsValue(value string) (int, error) {
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("--jobs requires a non-negative integer")
	}
	return n, nil
}

// stripJobsFlag removes --jobs N (or --jobs=N) from args, returning the parsed
// value and the remaining arguments in order. Every command that accepts the
// cap goes through it, so both spellings behave identically everywhere.
func stripJobsFlag(args []string) (jobs int, rest []string, err error) {
	rest = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; {
		case arg == "--jobs":
			if i+1 >= len(args) {
				return 0, nil, fmt.Errorf("--jobs requires a non-negative integer")
			}
			i++
			if jobs, err = parseJobsValue(args[i]); err != nil {
				return 0, nil, err
			}
		case strings.HasPrefix(arg, "--jobs="):
			if jobs, err = parseJobsValue(strings.TrimPrefix(arg, "--jobs=")); err != nil {
				return 0, nil, err
			}
		default:
			rest = append(rest, arg)
		}
	}
	return jobs, rest, nil
}

// parseOnlyJobsArgs accepts --jobs and rejects every other argument, for the
// commands whose only option is the cap.
func parseOnlyJobsArgs(args []string, command string) (int, error) {
	jobs, rest, err := stripJobsFlag(args)
	if err != nil {
		return 0, err
	}
	if len(rest) > 0 {
		return 0, fmt.Errorf("unknown %s option %q", command, rest[0])
	}
	return jobs, nil
}

// capProcessCPU applies an explicit --jobs cap to everything a command can
// spend CPU on, not only to rule goroutines. The engine semaphore bounds
// in-process rule analysis, but commands also do unbounded work of their own:
// dependency analysis, semantic loading, and the subprocesses they shell out
// to (git for the file inventory, go vet / go test ./... under --profile full,
// repair's verification run, gitleaks/gosec/osv-scanner under --with-tools, and
// go list for the semantic tier). The Go tools default to one worker per core,
// so without this a --jobs 2 run still saturates the machine whenever a child
// runs, which is the bulk of the lock-up under --profile full.
//
// Only Go programs honour these settings. git is a C program and any scanner
// that is not Go-built ignores both; they are short-lived and left alone.
//
// jobs <= 0 means auto (all cores, historical behaviour) and changes nothing.
// Calling it more than once is safe: repeating the same cap is a no-op.
func capProcessCPU(jobs int) {
	if jobs <= 0 {
		return
	}
	// Never raise the ceiling above the machine: GOMAXPROCS(4) on 2 cores makes
	// the runtime oversubscribe its Ps, and -p=4 above the core count only adds
	// build contention. Asking for more jobs than cores is not a request for more
	// parallelism than the hardware has.
	limit := jobs
	if cpus := runtime.NumCPU(); limit > cpus {
		limit = cpus
	}
	n := strconv.Itoa(limit)
	// In-process: rule fan-out (belt and braces), GC workers, semantic loaders.
	runtime.GOMAXPROCS(limit)
	// Children inherit the same ceiling; every Go tool the command invokes reads it.
	if os.Getenv("GOMAXPROCS") != n {
		_ = os.Setenv("GOMAXPROCS", n)
	}
	// go build/vet/test parallelism is -p, not GOMAXPROCS, so bound that too.
	// Append rather than parse and rebuild the value: the tool has no business
	// rewriting a user's GOFLAGS, and re-splitting silently collapses their
	// spacing. Duplicate flags are accepted, and go applies the later -p.
	override := "-p=" + n
	goflags := strings.TrimSpace(os.Getenv("GOFLAGS"))
	if goflags == override || strings.HasSuffix(goflags, " "+override) {
		return // already capped at this level; do not grow the value
	}
	if goflags != "" {
		goflags += " "
	}
	_ = os.Setenv("GOFLAGS", goflags+override)
}

// cappedEngine builds an engine whose rule fan-out honours --jobs, so every
// command that runs rules applies the same cap.
func cappedEngine(jobs int, rules ...review.Rule) *review.Engine {
	engine := review.NewEngine(rules...)
	engine.SetMaxParallel(jobs)
	return engine
}
