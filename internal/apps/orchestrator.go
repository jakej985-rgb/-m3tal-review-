package apps

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

// Run discovers apps, routes files, executes apps in parallel, and merges results.
func Run(ctx context.Context, cfg RunConfig, files []protocol.File) (RunReport, error) {
	reg, err := LoadRegistry()
	if err != nil {
		return RunReport{ExitCode: protocol.ExitError}, err
	}

	discovered, discDiags, err := Discover(ctx, cfg)
	if err != nil {
		code := protocol.ExitError
		if appErr, ok := err.(*Error); ok {
			code = appErr.Code
		}
		return RunReport{Diagnostics: discDiags, ExitCode: code}, err
	}

	plan := Route(discovered, reg, files)
	routed := make(map[string]bool)
	for _, list := range plan.ByApp {
		for _, f := range list {
			routed[f.Path] = true
		}
	}
	report := RunReport{
		Diagnostics:   append(discDiags, plan.Diagnostics...),
		MissingClaims: plan.MissingClaims,
		RoutedFiles:   routed,
	}
	for _, mc := range plan.MissingClaims {
		report.UnanalyzedFiles = append(report.UnanalyzedFiles, mc.Files...)
		report.ExitCode = maxExitPrecedence(report.ExitCode, protocol.ExitError)
	}

	if len(plan.AppOrder) == 0 {
		return report, nil
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if timeout > MaxTimeout {
		timeout = MaxTimeout
	}

	results := make([]AppResult, len(plan.AppOrder))
	var wg sync.WaitGroup
	for i, app := range plan.AppOrder {
		wg.Add(1)
		go func(idx int, a App) {
			defer wg.Done()
			results[idx] = runSingleApp(ctx, cfg, a, plan.ByApp[a.Name], timeout)
		}(i, app)
	}
	wg.Wait()

	report.Apps = results
	for _, res := range results {
		report.ExitCode = maxExitPrecedence(report.ExitCode, res.ExitCode)
		if res.Status == "ok" {
			report.Findings = append(report.Findings, res.Output.Findings...)
			report.Diagnostics = append(report.Diagnostics, res.Output.Diagnostics...)
			for _, u := range res.Output.Unanalyzed {
				report.UnanalyzedFiles = append(report.UnanalyzedFiles, u.File)
			}
		}
	}

	sortFindings(report.Findings)
	return report, nil
}

func runSingleApp(ctx context.Context, cfg RunConfig, app App, files []protocol.File, timeout time.Duration) AppResult {
	start := time.Now()
	req := protocol.Input{
		Protocol: protocol.Version,
		Run: protocol.RunInfo{
			Root:  cfg.Root,
			Scope: cfg.Scope,
			Mode:  cfg.Mode,
		},
		Config:            cfg.PerAppConfig[app.Name],
		Files:             files,
		DiagnosticsWanted: cfg.DiagnosticsWanted,
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return AppResult{
			App:      app,
			Status:   "failed",
			ExitCode: protocol.ExitError,
			Duration: time.Since(start),
			Err:      err,
		}
	}

	sent := make(map[string]struct{}, len(files))
	for _, f := range files {
		sent[f.Path] = struct{}{}
	}

	stdout, stderrTail, exitCode, runErr := runProcess(ctx, app.Path, nil, payload, protocol.MaxStdoutBytes, timeout)
	dur := time.Since(start)

	if exitCode == protocol.ExitTimeout {
		return AppResult{
			App:        app,
			Status:     "timeout",
			ExitCode:   protocol.ExitTimeout,
			Duration:   dur,
			StderrTail: stderrTail,
			Err:        runErr,
		}
	}
	if exitCode == protocol.ExitProtocol {
		return AppResult{
			App:        app,
			Status:     "protocol",
			ExitCode:   protocol.ExitProtocol,
			Duration:   dur,
			StderrTail: stderrTail,
			Err:        runErr,
		}
	}
	if exitCode != protocol.ExitClean && exitCode != protocol.ExitFindings {
		return AppResult{
			App:        app,
			Status:     "failed",
			ExitCode:   protocol.ExitError,
			Duration:   dur,
			StderrTail: stderrTail,
			Err:        fmt.Errorf("exit %d: %w", exitCode, runErr),
		}
	}

	out, decErr := protocol.DecodeOutput(stdout, app.Name, sent)
	if decErr == nil {
		decErr = protocol.ValidateOutputAgainstDescribe(out, protocol.DescribeResult{
			Protocol:   protocol.Version,
			Kind:       protocol.Kind,
			App:        protocol.AppInfo{Name: app.Name, Version: app.Version},
			Extensions: app.Extensions,
			Inputs:     app.Inputs,
			Rules:      app.Rules,
		}, sent)
	}
	if decErr != nil {
		return AppResult{
			App:        app,
			Status:     "protocol",
			ExitCode:   protocol.ExitProtocol,
			Duration:   dur,
			StderrTail: stderrTail,
			Err:        decErr,
		}
	}

	return AppResult{
		App:        app,
		Status:     "ok",
		ExitCode:   exitCode,
		Duration:   dur,
		Output:     out,
		StderrTail: stderrTail,
	}
}

func maxExitPrecedence(a, b int) int {
	// Precedence: 4 > 3 > 2 > 1 > 0
	if a > b {
		return a
	}
	return b
}

func severityRank(s string) int {
	switch s {
	case protocol.SeverityCritical:
		return 0
	case protocol.SeverityHigh:
		return 1
	case protocol.SeverityMedium:
		return 2
	case protocol.SeverityLow:
		return 3
	case protocol.SeverityInfo:
		return 4
	default:
		return 5
	}
}

func sortFindings(findings []protocol.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		ra, rb := severityRank(a.Severity), severityRank(b.Severity)
		if ra != rb {
			return ra < rb
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Message < b.Message
	})
}
