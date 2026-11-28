package languages

import (
	"context"

	"github.com/jakej985-rgb/m3tal-review/internal/analyzers"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/cpp"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/golang"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/jvm"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/python"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/rust"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/ts"
	"github.com/jakej985-rgb/m3tal-review/internal/planning"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
	"github.com/jakej985-rgb/m3tal-review/protocol"
)

type protocolRunner func(protocol.Input) protocol.Output

type protocolAdapter struct {
	meta planning.AnalyzerMetadata
	run  protocolRunner
}

func (a protocolAdapter) Metadata() planning.AnalyzerMetadata {
	return a.meta
}

func (a protocolAdapter) Analyze(_ context.Context, req analyzers.Request) (analyzers.Result, error) {
	pFiles := make([]protocol.File, 0, len(req.Files))
	for _, f := range req.Files {
		pFiles = append(pFiles, protocol.File{
			Path:    f.Path,
			Status:  "modified",
			Content: f.Content,
		})
	}
	out := a.run(protocol.Input{
		Protocol: protocol.Version,
		Run:      protocol.RunInfo{Root: req.Root, Scope: "working-tree", Mode: "review"},
		Files:    pFiles,
	})
	findings := make([]review.Finding, 0, len(out.Findings))
	for _, f := range out.Findings {
		findings = append(findings, review.Finding{
			Rule:        f.Rule,
			Category:    f.Category,
			Severity:    f.Severity,
			Confidence:  f.Confidence,
			File:        f.File,
			Line:        f.Line,
			Message:     f.Message,
			Remediation: f.Remediation,
			Signature:   f.Fingerprint,
			Snippet:     f.Evidence,
		})
	}
	return analyzers.Result{AnalyzerID: a.meta.ID, Findings: findings}, nil
}

// RegisterAll registers all Tier 1 language analyzers into reg.
func RegisterAll(reg *analyzers.Registry) {
	reg.Register(protocolAdapter{
		meta: planning.AnalyzerMetadata{
			ID: "lang-go", Name: "Go language analysis", Kind: planning.KindLanguage,
			Languages: []string{"Go"}, Capabilities: []string{"ast", "static", "semantic", "repair"},
			Description: "Go AST, correctness, security, and slop analysis",
		},
		run: golang.Run,
	})
	reg.Register(protocolAdapter{
		meta: planning.AnalyzerMetadata{
			ID: "lang-python", Name: "Python language analysis", Kind: planning.KindLanguage,
			Languages: []string{"Python"}, Capabilities: []string{"ast", "static", "repair"},
			Description: "Python AST, security, and slop analysis",
		},
		run: (python.App{}).Run,
	})
	reg.Register(protocolAdapter{
		meta: planning.AnalyzerMetadata{
			ID: "lang-js", Name: "JavaScript language analysis", Kind: planning.KindLanguage,
			Languages: []string{"JavaScript"}, Capabilities: []string{"ast", "static"},
			Description: "JavaScript security, bug, and slop analysis",
		},
		run: (ts.App{}).Run,
	})
	reg.Register(protocolAdapter{
		meta: planning.AnalyzerMetadata{
			ID: "lang-ts", Name: "TypeScript language analysis", Kind: planning.KindLanguage,
			Languages: []string{"TypeScript"}, Capabilities: []string{"ast", "static"},
			Description: "TypeScript security, bug, and slop analysis",
		},
		run: (ts.App{}).Run,
	})
	reg.Register(DartAnalyzer{})
	reg.Register(protocolAdapter{
		meta: planning.AnalyzerMetadata{
			ID: "lang-rust", Name: "Rust language analysis", Kind: planning.KindLanguage,
			Languages: []string{"Rust"}, Capabilities: []string{"static"},
			Description: "Rust safety, FFI, and async lock analysis",
		},
		run: (rust.App{}).Run,
	})
	reg.Register(protocolAdapter{
		meta: planning.AnalyzerMetadata{
			ID: "lang-java", Name: "Java language analysis", Kind: planning.KindLanguage,
			Languages: []string{"Java"}, Capabilities: []string{"static"},
			Description: "Java security and concurrency analysis",
		},
		run: (jvm.App{}).Run,
	})
	reg.Register(protocolAdapter{
		meta: planning.AnalyzerMetadata{
			ID: "lang-cpp", Name: "C/C++ language analysis", Kind: planning.KindLanguage,
			Languages: []string{"C", "C++"}, Capabilities: []string{"static"},
			Description: "C/C++ buffer, exec, and header analysis",
		},
		run: (cpp.App{}).Run,
	})
}
