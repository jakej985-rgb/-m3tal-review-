// Package safetext escapes control characters before text is written to a
// terminal or log line.
package safetext

import (
	"fmt"
	"strings"
	"unicode"
)

// Terminal escapes control characters in value.
func Terminal(value string) string {
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
