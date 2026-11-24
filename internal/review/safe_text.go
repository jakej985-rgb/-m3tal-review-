package review

import (
	"path"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/safetext"
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
	return safetext.Terminal(value)
}
