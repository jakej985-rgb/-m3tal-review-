package review

import "context"

type Rule interface {
	Name() string
	Check(diff string) []Finding
}

// ContextualRule is implemented by rules that can abort early when the
// provided context is cancelled or its deadline passes. checkRuleSafely
// prefers CheckContext so a rule timeout actually stops in-flight work
// instead of only abandoning the goroutine. Rules that only implement
// Rule keep the previous behavior: the timeout still yields a timeout
// finding, but the worker goroutine is not interruptible.
type ContextualRule interface {
	Rule
	CheckContext(ctx context.Context, diff string) []Finding
}
