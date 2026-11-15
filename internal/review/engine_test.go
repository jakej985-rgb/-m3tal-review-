package review

import (
	"context"
	"testing"
	"time"
)

func TestEngineRunsRules(t *testing.T) {
	engine := NewEngine(TodoRule{})

	diff := `diff --git a/example.go b/example.go
--- a/example.go
+++ b/example.go
@@ -1,1 +1,2 @@
 package main
+// TODO: finish this
`

	findings := engine.Run(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Rule != "todo-marker" {
		t.Errorf("expected todo-marker, got %q", findings[0].Rule)
	}
}

func TestEngineWithNoRules(t *testing.T) {
	engine := NewEngine()

	findings := engine.Run("some diff")

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestEngineRulePanicBecomesFinding(t *testing.T) {
	engine := NewEngine(panicRule{})
	findings := engine.Run("diff --git a/x b/x\n")
	if len(findings) != 1 || findings[0].Rule != "panic-rule-error" {
		t.Fatalf("findings = %+v", findings)
	}
}

type panicRule struct{}

func (panicRule) Name() string           { return "panic-rule" }
func (panicRule) Check(string) []Finding { panic("boom") }

// blockingContextualRule blocks until its context is cancelled, proving
// that checkRuleSafely's timeout reaches ContextualRule implementations
// instead of only abandoning the goroutine.
type blockingContextualRule struct {
	cancelled chan struct{}
}

func (blockingContextualRule) Name() string { return "blocking-test" }
func (r blockingContextualRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}
func (r blockingContextualRule) CheckContext(ctx context.Context, diff string) []Finding {
	<-ctx.Done()
	close(r.cancelled)
	return nil
}

func TestCheckRuleSafelyTimeoutCancelsContextualRule(t *testing.T) {
	old := ruleTimeout
	ruleTimeout = 50 * time.Millisecond
	defer func() { ruleTimeout = old }()

	rule := blockingContextualRule{cancelled: make(chan struct{})}
	findings := checkRuleSafely(context.Background(), rule, "diff")

	if len(findings) != 1 || findings[0].Rule != "blocking-test-timeout" {
		t.Fatalf("expected timeout finding, got %+v", findings)
	}
	select {
	case <-rule.cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("contextual rule was not cancelled by the rule timeout")
	}
}

func TestCheckRuleSafelyParentCancelReturnsNil(t *testing.T) {
	old := ruleTimeout
	ruleTimeout = time.Minute
	defer func() { ruleTimeout = old }()

	ctx, cancel := context.WithCancel(context.Background())
	rule := blockingContextualRule{cancelled: make(chan struct{})}
	done := make(chan []Finding, 1)
	go func() { done <- checkRuleSafely(ctx, rule, "diff") }()
	cancel()
	select {
	case findings := <-done:
		if findings != nil {
			t.Fatalf("expected nil findings on parent cancel, got %+v", findings)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("checkRuleSafely did not return after parent cancellation")
	}
}
