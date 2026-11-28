package ts

import (
	"testing"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

func TestTemplateExpressionsAndEscapedNewlines(t *testing.T) {
	src := "const a = \"line1\\\nline2\";\nconst b = `hello ${eval(input)} world`;\n"
	out := (App{}).Run(protocol.Input{
		Protocol: protocol.Version,
		Files: []protocol.File{{
			Path:    "index.ts",
			Status:  "added",
			Content: src,
		}},
	})
	var found bool
	for _, f := range out.Findings {
		if f.Rule == "ts/security/eval-call" && f.Line == 3 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ts/security/eval-call on line 3 inside template expression, got %+v", out.Findings)
	}
}

func TestRegexBraceInsideTemplateDoesNotHideLaterCode(t *testing.T) {
	src := "const text = `${/\\{/.test(value)}`;\neval(input);\n"
	out := (App{}).Run(protocol.Input{
		Protocol: protocol.Version,
		Files: []protocol.File{{
			Path:    "regex.ts",
			Status:  "added",
			Content: src,
		}},
	})
	var found bool
	for _, f := range out.Findings {
		if f.Rule == "ts/security/eval-call" && f.Line == 2 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ts/security/eval-call on line 2 after regex in template, got %+v", out.Findings)
	}
}
