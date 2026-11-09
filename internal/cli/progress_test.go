package cli

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestIsProgressEnabled(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name        string
		explicit    *bool
		format      string
		stdoutIsTTY bool
		want        bool
	}{
		{
			name:        "explicit progress true overrides non-TTY",
			explicit:    &trueVal,
			format:      "text",
			stdoutIsTTY: false,
			want:        true,
		},
		{
			name:        "explicit progress true overrides json format",
			explicit:    &trueVal,
			format:      "json",
			stdoutIsTTY: false,
			want:        true,
		},
		{
			name:        "explicit progress false overrides TTY text",
			explicit:    &falseVal,
			format:      "text",
			stdoutIsTTY: true,
			want:        false,
		},
		{
			name:        "auto disabled when stdout is not a TTY",
			explicit:    nil,
			format:      "text",
			stdoutIsTTY: false,
			want:        false,
		},
		{
			name:        "auto disabled for sarif format even on TTY",
			explicit:    nil,
			format:      "sarif",
			stdoutIsTTY: true,
			want:        false,
		},
		{
			name:        "auto disabled for json format even on TTY",
			explicit:    nil,
			format:      "json",
			stdoutIsTTY: true,
			want:        false,
		},
		{
			name:        "auto disabled for jsonl format even on TTY",
			explicit:    nil,
			format:      "jsonl",
			stdoutIsTTY: true,
			want:        false,
		},
		{
			name:        "auto disabled for junit format even on TTY",
			explicit:    nil,
			format:      "junit",
			stdoutIsTTY: true,
			want:        false,
		},
		{
			name:        "auto disabled for codeclimate format even on TTY",
			explicit:    nil,
			format:      "codeclimate",
			stdoutIsTTY: true,
			want:        false,
		},
		{
			name:        "auto enabled for text format on TTY",
			explicit:    nil,
			format:      "text",
			stdoutIsTTY: true,
			want:        true,
		},
		{
			name:        "auto enabled for empty format default on TTY",
			explicit:    nil,
			format:      "",
			stdoutIsTTY: true,
			want:        true,
		},
		{
			name:        "auto enabled for github format on TTY",
			explicit:    nil,
			format:      "github",
			stdoutIsTTY: true,
			want:        true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsProgressEnabled(tc.explicit, tc.format, tc.stdoutIsTTY)
			if got != tc.want {
				t.Errorf("IsProgressEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestProgressTrackerOutput(t *testing.T) {
	var buf bytes.Buffer
	tracker := NewProgressTracker(&buf, true)

	if !tracker.IsEnabled() {
		t.Errorf("expected tracker to be enabled")
	}

	tracker.Stage(1, 4, "Discovering files")
	tracker.FileTick(1, 100, "main.go")
	tracker.FileTick(50, 100, "util.go")
	tracker.FileTick(100, 100, "last.go")
	tracker.Tick("External scanner check")
	tracker.Done("Completed successfully")

	output := buf.String()
	if !strings.Contains(output, "[1/4] Discovering files...") {
		t.Errorf("missing stage indicator in output: %s", output)
	}
	if !strings.Contains(output, "Scanned 1/100 files") {
		t.Errorf("missing file tick 1 in output: %s", output)
	}
	if !strings.Contains(output, "Scanned 50/100 files") {
		t.Errorf("missing file tick 50 in output: %s", output)
	}
	if !strings.Contains(output, "Scanned 100/100 files") {
		t.Errorf("missing file tick 100 in output: %s", output)
	}
	if !strings.Contains(output, "-> External scanner check") {
		t.Errorf("missing tick message in output: %s", output)
	}
	if !strings.Contains(output, "[progress] Completed successfully") {
		t.Errorf("missing done message in output: %s", output)
	}
}

func TestProgressTrackerDisabled(t *testing.T) {
	var buf bytes.Buffer
	tracker := NewProgressTracker(&buf, false)

	if tracker.IsEnabled() {
		t.Errorf("expected tracker to be disabled")
	}

	tracker.Stage(1, 4, "Stage 1")
	tracker.FileTick(1, 10, "foo.go")
	tracker.Tick("sub task")
	tracker.Done("all done")

	if buf.Len() > 0 {
		t.Errorf("expected no output when disabled, got: %s", buf.String())
	}
}

func TestProgressTrackerConcurrency(t *testing.T) {
	var buf bytes.Buffer
	tracker := NewProgressTracker(&buf, true)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			tracker.Stage(id%4+1, 4, "Concurrent stage")
			tracker.FileTick(id*10, 200, "file.go")
			tracker.Tick("concurrent tick")
		}(i)
	}
	wg.Wait()

	if buf.Len() == 0 {
		t.Errorf("expected concurrent output in buffer")
	}
}

func TestParseProgressFlags(t *testing.T) {
	// Review options
	opts, err := parseReviewOptions([]string{"--progress"})
	if err != nil {
		t.Fatalf("parseReviewOptions with --progress: %v", err)
	}
	if opts.Progress == nil || !*opts.Progress {
		t.Errorf("expected opts.Progress to be true, got %v", opts.Progress)
	}

	optsNo, err := parseReviewOptions([]string{"--no-progress"})
	if err != nil {
		t.Fatalf("parseReviewOptions with --no-progress: %v", err)
	}
	if optsNo.Progress == nil || *optsNo.Progress {
		t.Errorf("expected optsNo.Progress to be false, got %v", optsNo.Progress)
	}

	// Audit options
	auditOpts, err := parseAuditOptions([]string{"--progress"})
	if err != nil {
		t.Fatalf("parseAuditOptions with --progress: %v", err)
	}
	if auditOpts.Progress == nil || !*auditOpts.Progress {
		t.Errorf("expected auditOpts.Progress to be true, got %v", auditOpts.Progress)
	}

	auditOptsNo, err := parseAuditOptions([]string{"--no-progress"})
	if err != nil {
		t.Fatalf("parseAuditOptions with --no-progress: %v", err)
	}
	if auditOptsNo.Progress == nil || *auditOptsNo.Progress {
		t.Errorf("expected auditOptsNo.Progress to be false, got %v", auditOptsNo.Progress)
	}
}
