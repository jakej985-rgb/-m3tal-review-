package cli

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// capAuditCPU applies an explicit --jobs cap to everything an audit can spend
// CPU on, not only to rule goroutines. The engine semaphore bounds in-process
// rule analysis, but an audit also shells out: git for the file inventory, go
// vet / go test ./... under --profile full, gitleaks/gosec/osv-scanner under
// --with-tools, and go list for the semantic tier. Each of those is a Go
// program that defaults to one worker per core, so without this a --jobs 2
// audit still saturates the machine whenever a child is running, which is the
// bulk of the lock-up on --profile full.
//
// jobs <= 0 means auto (all cores, historical behaviour) and changes nothing.
func capAuditCPU(jobs int) {
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
	// Children inherit the same ceiling; every Go tool the audit invokes reads it.
	_ = os.Setenv("GOMAXPROCS", n)
	// go build/vet/test parallelism is -p, not GOMAXPROCS, so bound that too.
	// Append rather than parse and rebuild the value: the audit has no business
	// rewriting a user's GOFLAGS, and re-splitting silently collapses their
	// spacing. Duplicate flags are accepted, and go applies the later -p.
	goflags := strings.TrimSpace(os.Getenv("GOFLAGS"))
	if goflags != "" {
		goflags += " "
	}
	_ = os.Setenv("GOFLAGS", goflags+"-p="+n)
}
