package plugin

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

const (
	DefaultPluginTimeout = 30 * time.Second
	MaxPluginTimeout     = 5 * time.Minute
)

// ExecutePlugin runs an analyzer plugin with bounded timeouts, error isolation, panic recovery,
// and result normalization. Crashes or timeouts in plugins will not crash the host runner.
func ExecutePlugin(ctx context.Context, p AnalyzerPlugin, in PluginInput) PluginOutput {
	if p == nil {
		return PluginOutput{
			Success: false,
			Error:   "nil plugin supplied to executor",
		}
	}

	meta := p.Metadata()
	startTime := time.Now()

	// Calculate bounded timeout
	timeout := in.Timeout
	if timeout <= 0 {
		timeout = DefaultPluginTimeout
	}
	if timeout > MaxPluginTimeout {
		timeout = MaxPluginTimeout
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type execResult struct {
		out PluginOutput
		err error
	}

	resultCh := make(chan execResult, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				stack := string(debug.Stack())
				resultCh <- execResult{
					out: PluginOutput{
						Success: false,
						Error:   fmt.Sprintf("plugin %s panicked: %v", meta.Name, r),
						Message: fmt.Sprintf("crash stack:\n%s", stack),
					},
					err: fmt.Errorf("plugin panic: %v", r),
				}
			}
		}()

		out, err := p.Analyze(ctxTimeout, in)
		resultCh <- execResult{out: out, err: err}
	}()

	var finalOut PluginOutput

	select {
	case <-ctxTimeout.Done():
		duration := time.Since(startTime)
		msg := fmt.Sprintf("plugin %s exceeded timeout of %v", meta.Name, timeout)
		if ctx.Err() != nil && ctx.Err() != context.DeadlineExceeded {
			msg = fmt.Sprintf("plugin %s cancelled: %v", meta.Name, ctx.Err())
		}
		finalOut = PluginOutput{
			Success:  false,
			Error:    msg,
			Duration: duration,
			Checks: []review.CheckResult{
				{
					Name:     meta.Name,
					Category: "plugin",
					Status:   "failed",
					Message:  msg,
					Version:  meta.Version,
				},
			},
			Findings: []review.Finding{
				{
					Category:    "confidence",
					Rule:        "plugin-" + meta.Name,
					Severity:    "high",
					Message:     fmt.Sprintf("Analyzer plugin %s failed to complete: %s", meta.Name, msg),
					Remediation: "Inspect plugin logs, adjust timeout, or verify plugin stability.",
				},
			},
		}

	case res := <-resultCh:
		duration := time.Since(startTime)
		finalOut = res.out
		finalOut.Duration = duration

		if res.err != nil {
			finalOut.Success = false
			if finalOut.Error == "" {
				finalOut.Error = res.err.Error()
			}
			finalOut.Checks = append(finalOut.Checks, review.CheckResult{
				Name:     meta.Name,
				Category: "plugin",
				Status:   "failed",
				Message:  finalOut.Error,
				Version:  meta.Version,
			})
			finalOut.Findings = append(finalOut.Findings, review.Finding{
				Category:    "confidence",
				Rule:        "plugin-" + meta.Name,
				Severity:    "high",
				Message:     fmt.Sprintf("Analyzer plugin %s encountered an error: %s", meta.Name, finalOut.Error),
				Remediation: "Check plugin requirements or run without this plugin.",
			})
		} else {
			finalOut.Success = true
		}
	}

	return NormalizePluginOutput(meta, finalOut, in.RepositoryRoot)
}
