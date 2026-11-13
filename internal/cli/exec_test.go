package cli

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRunCommandSubprocessCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Start a command that would sleep/block
	var cmdName string
	var cmdArgs []string

	if runtime.GOOS == "windows" {
		cmdName = "ping"
		cmdArgs = []string{"-n", "10", "127.0.0.1"}
	} else {
		cmdName = "sh"
		cmdArgs = []string{"-c", "sleep 10"}
	}

	// Verify command executable exists before testing
	if _, err := exec.LookPath(cmdName); err != nil {
		t.Skipf("%s not available: %v", cmdName, err)
	}

	start := time.Now()
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	tempDir := t.TempDir()
	out, err := runCommand(ctx, tempDir, append([]string{cmdName}, cmdArgs...)...)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected error from cancelled command, but got nil; out: %s", string(out))
	}

	if !strings.Contains(err.Error(), "cancelled") && !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("expected cancellation message, got: %v", err)
	}

	if elapsed > 2*time.Second {
		t.Errorf("command took too long to terminate after cancellation: %v", elapsed)
	}
}

func TestRunCommandOutputCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var cmdName string
	var cmdArgs []string

	if runtime.GOOS == "windows" {
		cmdName = "ping"
		cmdArgs = []string{"-n", "10", "127.0.0.1"}
	} else {
		cmdName = "sh"
		cmdArgs = []string{"-c", "sleep 10"}
	}

	if _, err := exec.LookPath(cmdName); err != nil {
		t.Skipf("%s not available: %v", cmdName, err)
	}

	tempDir := t.TempDir()
	_, err := runCommandOutput(ctx, tempDir, append([]string{cmdName}, cmdArgs...)...)
	if err == nil {
		t.Fatal("expected error on timeout, got nil")
	}

	if !strings.Contains(err.Error(), "cancelled") && !strings.Contains(err.Error(), "deadline exceeded") {
		t.Errorf("expected deadline exceeded or cancelled, got: %v", err)
	}
}
