package golang

import (
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

// Fix synthesizes deterministic patches for supported review-go findings.
func Fix(in protocol.FixInput) protocol.FixOutput {
	m := loadManifest()
	byPath := make(map[string][]string, len(in.Files))
	for _, f := range in.Files {
		byPath[f.Path] = strings.Split(f.Content, "\n")
	}

	var patches []protocol.Patch
	for _, fnd := range in.Findings {
		lines, ok := byPath[fnd.File]
		if !ok || fnd.Line < 1 || fnd.Line > len(lines) {
			continue
		}
		orig := lines[fnd.Line-1]
		switch fnd.Rule {
		case "go/slop/redundant-bool-compare":
			repl := strings.ReplaceAll(orig, " == true", "")
			repl = strings.ReplaceAll(repl, " != false", "")
			if repl != orig {
				patches = append(patches, protocol.Patch{
					Rule:        fnd.Rule,
					File:        fnd.File,
					StartLine:   fnd.Line,
					EndLine:     fnd.Line,
					Replacement: repl,
					Summary:     "Remove redundant boolean literal comparison",
				})
			}
		case "go/security/tls-insecure-skip-verify":
			repl := strings.ReplaceAll(orig, "InsecureSkipVerify: true", "InsecureSkipVerify: false")
			repl = strings.ReplaceAll(repl, "InsecureSkipVerify = true", "InsecureSkipVerify = false")
			if repl != orig {
				patches = append(patches, protocol.Patch{
					Rule:        fnd.Rule,
					File:        fnd.File,
					StartLine:   fnd.Line,
					EndLine:     fnd.Line,
					Replacement: repl,
					Summary:     "Disable InsecureSkipVerify",
				})
			}
		}
	}

	return protocol.FixOutput{
		Protocol: protocol.Version,
		App:      protocol.AppInfo{Name: m.Name, Version: m.Version},
		Patches:  patches,
	}
}
