package review

import (
	"context"
	"testing"
	"time"
)

// cooperativeRule returns an empty result immediately after its context
// is cancelled — the case where result and ctx.Done() race in select.
type cooperativeRule struct{}

func (cooperativeRule) Name() string               { return "coop-test" }
func (r cooperativeRule) Check(d string) []Finding { return r.CheckContext(context.Background(), d) }
func (cooperativeRule) CheckContext(ctx context.Context, _ string) []Finding {
	<-ctx.Done()
	return []Finding{}
}

func TestCheckRuleSafelyCooperativeTimeoutReportsTimeout(t *testing.T) {
	old := ruleTimeout
	ruleTimeout = 10 * time.Millisecond
	defer func() { ruleTimeout = old }()

	for i := 0; i < 50; i++ {
		findings := checkRuleSafely(context.Background(), cooperativeRule{}, "diff")
		if len(findings) != 1 || findings[0].Rule != "coop-test-timeout" {
			t.Fatalf("iteration %d: expected timeout finding, got %+v", i, findings)
		}
	}
}
