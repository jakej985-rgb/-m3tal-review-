package cli

import (
	"os"
	"runtime"
	"strconv"
	"testing"
)

func TestCapAuditCPUAppliesJobsToProcessAndChildren(t *testing.T) {
	original := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(original) })
	t.Setenv("GOMAXPROCS", "")
	t.Setenv("GOFLAGS", "-mod=mod")

	// One job never exceeds the core count, so this holds on any machine.
	capAuditCPU(1)

	if got := runtime.GOMAXPROCS(0); got != 1 {
		t.Fatalf("GOMAXPROCS after --jobs 1 = %d, want 1", got)
	}
	if got := os.Getenv("GOMAXPROCS"); got != "1" {
		t.Fatalf("child GOMAXPROCS = %q, want %q", got, "1")
	}
	if got := os.Getenv("GOFLAGS"); got != "-mod=mod -p=1" {
		t.Fatalf("child GOFLAGS = %q, want %q", got, "-mod=mod -p=1")
	}
}

// An existing -p is left alone and overridden by the appended one: go parses
// GOFLAGS with a flag set, where the last occurrence wins.
func TestCapAuditCPUAppendsAfterExistingParallelism(t *testing.T) {
	original := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(original) })
	t.Setenv("GOMAXPROCS", "")
	t.Setenv("GOFLAGS", "-p=8")

	capAuditCPU(2)

	want := "-p=8 -p=2"
	if got := os.Getenv("GOFLAGS"); got != want {
		t.Fatalf("child GOFLAGS = %q, want %q", got, want)
	}
}

// The user's GOFLAGS must reach the child byte-for-byte, with the cap merely
// appended: re-splitting the value would collapse spacing and re-join tokens.
func TestCapAuditCPUPreservesExistingGoflags(t *testing.T) {
	original := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(original) })
	t.Setenv("GOMAXPROCS", "")
	t.Setenv("GOFLAGS", "-mod=mod  -trimpath")

	capAuditCPU(1)

	want := "-mod=mod  -trimpath -p=1"
	if got := os.Getenv("GOFLAGS"); got != want {
		t.Fatalf("child GOFLAGS = %q, want %q", got, want)
	}
}

func TestCapAuditCPUClampsToAvailableCPUs(t *testing.T) {
	original := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(original) })
	t.Setenv("GOMAXPROCS", "")
	t.Setenv("GOFLAGS", "")

	cpus := runtime.NumCPU()
	capAuditCPU(cpus + 8)

	want := strconv.Itoa(cpus)
	if got := runtime.GOMAXPROCS(0); got != cpus {
		t.Fatalf("GOMAXPROCS for --jobs above core count = %d, want %d", got, cpus)
	}
	if got := os.Getenv("GOMAXPROCS"); got != want {
		t.Fatalf("child GOMAXPROCS = %q, want %q", got, want)
	}
	if got := os.Getenv("GOFLAGS"); got != "-p="+want {
		t.Fatalf("child GOFLAGS = %q, want %q", got, "-p="+want)
	}
}

func TestCapAuditCPUIgnoresAuto(t *testing.T) {
	before := runtime.GOMAXPROCS(0)
	t.Setenv("GOMAXPROCS", "untouched")
	t.Setenv("GOFLAGS", "-mod=mod")

	capAuditCPU(0)

	if got := runtime.GOMAXPROCS(0); got != before {
		t.Fatalf("GOMAXPROCS changed for --jobs 0: %d, want %d", got, before)
	}
	if got := os.Getenv("GOMAXPROCS"); got != "untouched" {
		t.Fatalf("child GOMAXPROCS modified for --jobs 0: %q", got)
	}
	if got := os.Getenv("GOFLAGS"); got != "-mod=mod" {
		t.Fatalf("child GOFLAGS modified for --jobs 0: %q", got)
	}
}
