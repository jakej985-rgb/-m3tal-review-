package apps

import (
	"context"
	"fmt"
	"time"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

// Describe invokes `<binPath> --describe` and validates the handshake response.
func Describe(ctx context.Context, binPath string) (App, error) {
	start := time.Now()
	stdout, stderrTail, exitCode, err := runProcess(ctx, binPath, []string{"--describe"}, nil, protocol.MaxStdoutBytes, DescribeTimeout)
	dur := time.Since(start)
	if err != nil {
		if exitCode == 3 {
			return App{}, &Error{Code: protocol.ExitTimeout, Err: fmt.Errorf("describe timed out: %w", err)}
		}
		if stderrTail != "" {
			return App{}, &Error{Code: protocol.ExitError, Err: fmt.Errorf("describe failed (exit %d): %s", exitCode, stderrTail)}
		}
		return App{}, &Error{Code: protocol.ExitError, Err: fmt.Errorf("describe failed (exit %d): %w", exitCode, err)}
	}

	res, err := protocol.DecodeDescribe(stdout)
	if err != nil {
		return App{}, &Error{Code: protocol.ExitProtocol, Err: fmt.Errorf("invalid describe output: %w", err)}
	}

	return App{
		Name:             res.App.Name,
		Version:          res.App.Version,
		Path:             binPath,
		Extensions:       res.Extensions,
		FilePatterns:     res.FilePatterns,
		Inputs:           res.Inputs,
		Capabilities:     res.Capabilities,
		Rules:            res.Rules,
		DescribeDuration: dur,
	}, nil
}
