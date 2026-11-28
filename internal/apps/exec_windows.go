//go:build windows

package apps

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const maxStderrBytes = 64 * 1024

type cappedBuffer struct {
	buf      bytes.Buffer
	limit    int
	overflow bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.limit <= 0 {
		return len(p), nil
	}
	rem := c.limit - c.buf.Len()
	if rem <= 0 {
		c.overflow = true
		return len(p), nil
	}
	if len(p) > rem {
		c.buf.Write(p[:rem])
		c.overflow = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

func runProcess(ctx context.Context, binPath string, args []string, stdinData []byte, stdoutLimit int, timeout time.Duration) (stdout []byte, stderrTail string, exitCode int, err error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, binPath, args...)
	cmd.Env = sanitizedEnv()
	if stdinData != nil {
		cmd.Stdin = bytes.NewReader(stdinData)
	}

	outBuf := &cappedBuffer{limit: stdoutLimit}
	errBuf := &cappedBuffer{limit: maxStderrBytes}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf

	waitErr := cmd.Run()
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return outBuf.buf.Bytes(), tailString(errBuf.buf.String(), 512), 3, fmt.Errorf("timeout after %s", timeout)
	}
	if outBuf.overflow {
		return nil, tailString(errBuf.buf.String(), 512), 4, fmt.Errorf("stdout exceeded %d bytes", stdoutLimit)
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 2
		}
		return outBuf.buf.Bytes(), tailString(errBuf.buf.String(), 512), exitCode, waitErr
	}
	return outBuf.buf.Bytes(), tailString(errBuf.buf.String(), 512), 0, nil
}

func sanitizedEnv() []string {
	keep := []string{"PATH", "HOME", "USERPROFILE", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "COMSPEC"}
	var env []string
	for _, k := range keep {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func tailString(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[len(s)-max:]
}
