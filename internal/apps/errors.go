package apps

import (
	"fmt"
	"strings"
)

// Error represents an app-layer failure with a protocol exit code.
type Error struct {
	Code int
	App  string
	Err  error
}

func (e *Error) Error() string {
	if e.App != "" && e.Err != nil {
		return fmt.Sprintf("%s failed: %v", e.App, e.Err)
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	if e.App != "" {
		return fmt.Sprintf("%s failed (exit %d)", e.App, e.Code)
	}
	return fmt.Sprintf("app error (exit %d)", e.Code)
}

func (e *Error) Unwrap() error {
	return e.Err
}

// MissingClaim records an extension required by the registry that has no discovered app.
type MissingClaim struct {
	App        string
	Extensions []string
	Files      []string
}

func (m MissingClaim) String() string {
	return fmt.Sprintf("no app for %s files (expected %s)", strings.Join(m.Extensions, ", "), m.App)
}
