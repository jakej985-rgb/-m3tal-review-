package review

import (
	"fmt"
	"path"
	"strings"
	"unicode"
)

func isCommentOnlyLine(file, text string) bool {
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*/") || strings.HasPrefix(trimmed, "* ") || strings.HasPrefix(trimmed, "<!--") {
		return true
	}
	switch strings.ToLower(path.Ext(file)) {
	case ".py", ".sh", ".bash", ".zsh", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".properties", ".env",
		".rb", ".rake", ".pl", ".pm", ".ex", ".exs", ".r", ".jl", ".nim", ".cr", ".tf", ".hcl", ".graphql", ".gql", ".fish":
		return strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";")
	case ".php", ".phtml":
		return strings.HasPrefix(trimmed, "#")
	default:
		return false
	}
}

func safeTerminalText(value string) string {
	var displayed strings.Builder
	for _, r := range value {
		if !unicode.IsControl(r) {
			displayed.WriteRune(r)
			continue
		}
		switch {
		case r <= 0xff:
			fmt.Fprintf(&displayed, "\\x%02x", r)
		case r <= 0xffff:
			fmt.Fprintf(&displayed, "\\u%04x", r)
		default:
			fmt.Fprintf(&displayed, "\\U%08x", r)
		}
	}
	return displayed.String()
}
