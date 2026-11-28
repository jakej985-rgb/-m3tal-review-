package defaultreg

import (
	"github.com/jakej985-rgb/m3tal-review/internal/analyzers"
	"github.com/jakej985-rgb/m3tal-review/internal/analyzers/crosslanguage"
	"github.com/jakej985-rgb/m3tal-review/internal/analyzers/frameworks"
	"github.com/jakej985-rgb/m3tal-review/internal/analyzers/infrastructure"
	"github.com/jakej985-rgb/m3tal-review/internal/analyzers/languages"
)

// New creates a Registry populated with all built-in language, framework,
// infrastructure, and cross-language analyzers.
func New() *analyzers.Registry {
	reg := analyzers.NewRegistry()
	languages.RegisterAll(reg)
	frameworks.RegisterAll(reg)
	infrastructure.RegisterAll(reg)
	crosslanguage.RegisterAll(reg)
	return reg
}
