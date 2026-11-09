package cli

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// maxCapturedOutput bounds how much stdout+stderr a review-spawned command may
// buffer. Reviewed repositories are untrusted: a `go test` or scanner that
// floods output must not exhaust memory.
const maxCapturedOutput = 1 << 20 // 1 MiB

// cappedBuffer discards bytes past the limit while still reporting the full
// length to the writer contract, so commands do not block on a full pipe.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if remaining := b.limit - b.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			b.buf.Write(p[:remaining])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *cappedBuffer) Bytes() []byte  { return b.buf.Bytes() }
func (b *cappedBuffer) String() string { return b.buf.String() }

// runCommand executes args in dir and returns up to maxCapturedOutput bytes of
// combined stdout+stderr.
func runCommand(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = dir
	cmd.WaitDelay = 1 * time.Second
	var out cappedBuffer
	out.limit = maxCapturedOutput
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if ctx.Err() != nil {
		return out.Bytes(), fmt.Errorf("subprocess cancelled: %w", ctx.Err())
	}
	return out.Bytes(), err
}

// runCommandOutput is like runCommand but captures only stdout; stderr is
// appended to the returned error so JSON-producing tools keep clean output.
func runCommandOutput(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = dir
	cmd.WaitDelay = 1 * time.Second
	var out, errOut cappedBuffer
	out.limit = maxCapturedOutput
	errOut.limit = maxCapturedOutput
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	if ctx.Err() != nil {
		return out.Bytes(), fmt.Errorf("subprocess cancelled: %w", ctx.Err())
	}
	if err != nil && errOut.buf.Len() > 0 {
		err = fmt.Errorf("%w: %s", err, errOut.String())
	}
	return out.Bytes(), err
}
