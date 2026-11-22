package review

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	rules       []Rule
	maxParallel int
}

func NewEngine(rules ...Rule) *Engine {
	return &Engine{
		rules: rules,
	}
}

// SetMaxParallel bounds how many rules analyse a diff at once. Zero or
// negative means runtime.GOMAXPROCS(0), which lets every rule run
// concurrently and is the historical behaviour. Lower values cap the CPU
// burst an audit produces on a shared machine, at the cost of wall time.
// Call it before Run/RunContext; Engine does not mutate maxParallel itself.
func (e *Engine) SetMaxParallel(n int) { e.maxParallel = n }

func (e *Engine) parallelism() int {
	if e.maxParallel > 0 {
		return e.maxParallel
	}
	return runtime.GOMAXPROCS(0)
}

func (e *Engine) Run(diff string) []Finding {
	return e.RunContext(context.Background(), diff)
}

// RunContext is Run with caller cancellation propagated to rules that
// implement ContextualRule.
func (e *Engine) RunContext(ctx context.Context, diff string) []Finding {
	// Rules are independent; run them concurrently but concatenate results
	// in registration order so output stays deterministic.
	limit := e.parallelism()
	if limit > len(e.rules) {
		limit = len(e.rules)
	}
	results := make([][]Finding, len(e.rules))
	var wg sync.WaitGroup
	var sem chan struct{}
	if limit > 0 && limit < len(e.rules) {
		sem = make(chan struct{}, limit)
	}
	for i, rule := range e.rules {
		if sem != nil {
			// Acquire before spawning so a capped run never leaves rule
			// goroutines parked behind the semaphore; checkRuleSafely
			// starts one of its own per rule for timeout enforcement.
			sem <- struct{}{}
		}
		wg.Add(1)
		go func(i int, rule Rule) {
			defer wg.Done()
			if sem != nil {
				defer func() { <-sem }()
			}
			results[i] = checkRuleSafely(ctx, rule, diff)
		}(i, rule)
	}
	wg.Wait()

	var findings []Finding
	for _, ruleFindings := range results {
		for i := range ruleFindings {
			if ruleFindings[i].Category == "" {
				ruleFindings[i].Category = categoryForRule(ruleFindings[i].Rule)
			}
		}
		findings = append(findings, ruleFindings...)
	}

	return findings
}

func categoryForRule(rule string) string {
	if strings.HasPrefix(rule, "gin-") || strings.HasPrefix(rule, "echo-") ||
		strings.HasPrefix(rule, "chi-") || strings.HasPrefix(rule, "fiber-") ||
		strings.HasPrefix(rule, "http-") {
		return "security"
	}
	switch rule {
	case "hardcoded-credential", "exposed-secret", "high-entropy-secret", "world-writable-file-mode", "insecure-tls-verification", "risky-shell-execution":
		return "security"
	case "review-risk":
		return "risk"
	case "review-policy", "agent-spec-contract":
		return "drift"
	case "code-slop-analysis-error", "repository-lint", "review-policy-config-error":
		return "confidence"
	case "touch-target-size", "test-viewport-chrome-contract", "design-system-spec", "stale-state-invalidation", "resource-leak-disposable", "unmounted-async-gap", "hot-path-allocation":
		return "quality"
	default:
		return "review"
	}
}

// ruleTimeout bounds a single rule's analysis; a hung rule on hostile input
// yields a timeout finding instead of stalling the review forever.
// M3TAL_RULE_TIMEOUT (a Go duration) overrides the default.
var ruleTimeout = func() time.Duration {
	if v := os.Getenv("M3TAL_RULE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 2 * time.Minute
}()

var debugRules = os.Getenv("M3TAL_DEBUG") != ""

// RunRuleSafely executes a single rule with panic recovery and the
// per-rule timeout, for callers that must run rules outside Engine
// (e.g. package-scoped taint analysis over grouped diffs).
func RunRuleSafely(rule Rule, diff string) []Finding {
	return checkRuleSafely(context.Background(), rule, diff)
}

// checkRuleSafely runs a rule and converts a panic or timeout into a
// confidence finding so one buggy rule cannot crash or stall the review.
// The per-rule timeout is delivered through a context: rules implementing
// ContextualRule observe cancellation and stop work; other rules are
// bounded only by the returned timeout finding.
func checkRuleSafely(parent context.Context, rule Rule, diff string) (findings []Finding) {
	ctx, cancel := context.WithTimeout(parent, ruleTimeout)
	defer cancel()
	result := make(chan []Finding, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				result <- []Finding{{
					Rule:        rule.Name() + "-error",
					Severity:    "medium",
					Message:     "Rule " + rule.Name() + " failed during analysis",
					Remediation: "Report this as a bug; the rule may have hit an unhandled edge case.",
				}}
			}
		}()
		if cr, ok := rule.(ContextualRule); ok {
			result <- cr.CheckContext(ctx, diff)
		} else {
			result <- rule.Check(diff)
		}
	}()
	start := time.Now()
	select {
	case findings = <-result:
		// A cooperative rule may return partial results right after its
		// deadline; both select cases can be ready, so recheck here.
		if ctx.Err() != nil {
			if parent.Err() != nil {
				return nil
			}
			return []Finding{{
				Rule:        rule.Name() + "-timeout",
				Severity:    "medium",
				Message:     "Rule " + rule.Name() + " exceeded the analysis time limit",
				Remediation: "Report this as a bug; the rule may be stuck on pathological input.",
			}}
		}
		if debugRules {
			fmt.Fprintf(os.Stderr, "rule %-28s %s %d findings\n", rule.Name(), time.Since(start).Round(time.Millisecond), len(findings))
		}
		return findings
	case <-ctx.Done():
		if parent.Err() != nil {
			return nil
		}
		return []Finding{{
			Rule:        rule.Name() + "-timeout",
			Severity:    "medium",
			Message:     "Rule " + rule.Name() + " exceeded the analysis time limit",
			Remediation: "Report this as a bug; the rule may be stuck on pathological input.",
		}}
	}
}
