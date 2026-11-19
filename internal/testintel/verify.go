package testintel

import (
	"context"
	"fmt"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// TestRunner executes targeted test runs within bounded time and isolation limits.
type TestRunner interface {
	RunTest(ctx context.Context, targetPkg, testName string) (bool, string, error)
}

// ReAnalyzer runs post-remediation analysis to detect remaining or collateral findings.
type ReAnalyzer interface {
	ReAnalyze(ctx context.Context) ([]review.Finding, error)
}

// VerifyOptions configures the verification execution.
type VerifyOptions struct {
	Timeout         time.Duration
	TargetPackage   string
	TargetTest      string
	BaselineFinding review.Finding
	PriorFindings   []review.Finding
}

// findRemaining checks if the baseline finding is still flagged in post-repair findings.
func findRemaining(targetID, targetRule, targetFile string, postFindings []review.Finding) bool {
	for _, f := range postFindings {
		if f.ID == targetID || (f.Rule == targetRule && f.File == targetFile) {
			return true
		}
	}
	return false
}

// detectCollateral identifies new findings introduced by the remediation.
func detectCollateral(prior, post []review.Finding) []review.Finding {
	priorSet := make(map[string]bool)
	for _, f := range prior {
		key := f.Rule + ":" + f.File + ":" + fmt.Sprint(f.Line)
		priorSet[key] = true
	}

	var collateral []review.Finding
	for _, f := range post {
		key := f.Rule + ":" + f.File + ":" + fmt.Sprint(f.Line)
		if !priorSet[key] {
			collateral = append(collateral, f)
		}
	}
	return collateral
}

// VerifyRemediation verifies a remediation through targeted test execution and re-analysis.
func VerifyRemediation(
	ctx context.Context,
	runner TestRunner,
	analyzer ReAnalyzer,
	opts VerifyOptions,
) VerificationResult {
	start := time.Now()
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	subCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var testsPassed bool
	var testOut string
	if runner != nil && opts.TargetTest != "" {
		passed, out, _ := runner.RunTest(subCtx, opts.TargetPackage, opts.TargetTest)
		testsPassed = passed
		testOut = out
	}

	var postFindings []review.Finding
	if analyzer != nil {
		findings, _ := analyzer.ReAnalyze(subCtx)
		postFindings = findings
	}

	findingStillExists := findRemaining(
		opts.BaselineFinding.ID,
		opts.BaselineFinding.Rule,
		opts.BaselineFinding.File,
		postFindings,
	)
	findingResolved := !findingStillExists
	collateral := detectCollateral(opts.PriorFindings, postFindings)

	var status ProofStatus
	switch {
	case findingResolved && testsPassed && len(collateral) == 0:
		status = ProofVerifiedAbsence
	case findingResolved || testsPassed:
		status = ProofPartiallyVerified
	default:
		status = ProofUnverified
	}

	epistemicLimits := fmt.Sprintf(
		"%s (Resolved=%t, TestsPassed=%t, CollateralFindings=%d)",
		EpistemicDisclaimer, findingResolved, testsPassed, len(collateral),
	)

	return VerificationResult{
		FindingID:          opts.BaselineFinding.ID,
		TestsPassed:        testsPassed,
		TestOutput:         testOut,
		FindingResolved:    findingResolved,
		CollateralFindings: collateral,
		Status:             status,
		EpistemicLimits:    epistemicLimits,
		ExecutionTime:      time.Since(start),
	}
}
