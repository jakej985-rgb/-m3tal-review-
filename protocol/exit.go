package protocol

// Process exit codes for the review-app invocation contract.
const (
	// ExitClean indicates analysis completed with no findings over threshold.
	ExitClean = 0
	// ExitFindings indicates analysis completed and the app's own threshold tripped.
	// The orchestrator treats this as a successful run and applies its own policy gate.
	ExitFindings = 1
	// ExitError indicates an app error or refusal (e.g. invalid config, missing binary).
	ExitError = 2
	// ExitTimeout indicates the app exceeded its execution deadline.
	ExitTimeout = 3
	// ExitProtocol indicates a protocol mismatch, malformed JSON, or invalid output.
	ExitProtocol = 4
)
