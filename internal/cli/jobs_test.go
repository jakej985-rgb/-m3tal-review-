package cli

import (
	"os"
	"runtime"
	"strconv"
	"testing"
)

func TestParseJobsValue(t *testing.T) {
	tests := []struct {
		value   string
		want    int
		wantErr bool
	}{
		{"0", 0, false},
		{"4", 4, false},
		{"100", 100, false},
		{"-1", 0, true},
		{"", 0, true},
		{"many", 0, true},
		{" 2", 0, true},
	}
	for _, tc := range tests {
		got, err := parseJobsValue(tc.value)
		if (err != nil) != tc.wantErr {
			t.Fatalf("parseJobsValue(%q) err = %v, wantErr %t", tc.value, err, tc.wantErr)
		}
		if !tc.wantErr && got != tc.want {
			t.Fatalf("parseJobsValue(%q) = %d, want %d", tc.value, got, tc.want)
		}
	}
}

// Repeating the same cap must not keep growing GOFLAGS.
func TestCapProcessCPUIsIdempotent(t *testing.T) {
	original := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(original) })
	t.Setenv("GOMAXPROCS", "")
	t.Setenv("GOFLAGS", "-mod=mod")

	capProcessCPU(1)
	first := os.Getenv("GOFLAGS")
	capProcessCPU(1)

	if first != "-mod=mod -p=1" {
		t.Fatalf("first cap = %q, want %q", first, "-mod=mod -p=1")
	}
	if got := os.Getenv("GOFLAGS"); got != first {
		t.Fatalf("second cap changed GOFLAGS: %q then %q", first, got)
	}
}

func TestCapProcessCPUAppliesJobsToProcessAndChildren(t *testing.T) {
	original := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(original) })
	t.Setenv("GOMAXPROCS", "")
	t.Setenv("GOFLAGS", "-mod=mod")

	// One job never exceeds the core count, so this holds on any machine.
	capProcessCPU(1)

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
func TestCapProcessCPUAppendsAfterExistingParallelism(t *testing.T) {
	original := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(original) })
	t.Setenv("GOMAXPROCS", "")
	t.Setenv("GOFLAGS", "-p=8")

	capProcessCPU(2)

	want := "-p=8 -p=2"
	if got := os.Getenv("GOFLAGS"); got != want {
		t.Fatalf("child GOFLAGS = %q, want %q", got, want)
	}
}

// The user's GOFLAGS must reach the child byte-for-byte, with the cap merely
// appended: re-splitting the value would collapse spacing and re-join tokens.
func TestCapProcessCPUPreservesExistingGoflags(t *testing.T) {
	original := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(original) })
	t.Setenv("GOMAXPROCS", "")
	t.Setenv("GOFLAGS", "-mod=mod  -trimpath")

	capProcessCPU(1)

	want := "-mod=mod  -trimpath -p=1"
	if got := os.Getenv("GOFLAGS"); got != want {
		t.Fatalf("child GOFLAGS = %q, want %q", got, want)
	}
}

func TestCapProcessCPUClampsToAvailableCPUs(t *testing.T) {
	original := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(original) })
	t.Setenv("GOMAXPROCS", "")
	t.Setenv("GOFLAGS", "")

	cpus := runtime.NumCPU()
	capProcessCPU(cpus + 8)

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

func TestCapProcessCPUIgnoresAuto(t *testing.T) {
	before := runtime.GOMAXPROCS(0)
	t.Setenv("GOMAXPROCS", "untouched")
	t.Setenv("GOFLAGS", "-mod=mod")

	capProcessCPU(0)

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
