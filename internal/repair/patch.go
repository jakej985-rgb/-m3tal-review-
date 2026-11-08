package repair

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ApplyProposalToFile applies the validated proposal to the target file inside the specified root directory.
func ApplyProposalToFile(root string, p *Proposal) error {
	if err := ValidatePatchBoundaries(root, p.TargetFile, p.Patch); err != nil {
		return fmt.Errorf("boundary validation failed: %w", err)
	}

	targetPath := filepath.Join(root, p.TargetFile)
	data, err := os.ReadFile(targetPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read target file %q: %w", targetPath, err)
	}

	newContent, err := ApplyProposalToContent(string(data), p)
	if err != nil {
		return fmt.Errorf("apply patch to %q: %w", targetPath, err)
	}

	// Ensure parent directories exist
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return fmt.Errorf("create parent directory for %q: %w", targetPath, err)
	}

	// Write updated file content
	if err := os.WriteFile(targetPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("write updated target file %q: %w", targetPath, err)
	}

	return nil
}

// ApplyProposalToContent applies a Proposal to original content.
func ApplyProposalToContent(originalContent string, p *Proposal) (string, error) {
	if p.ProposedContent != "" && (p.OriginalContent == "" || p.OriginalContent == originalContent) {
		return p.ProposedContent, nil
	}
	return ApplyPatchToContent(originalContent, p.Patch)
}

// ApplyPatchToContent applies a unified diff patch to original text.
func ApplyPatchToContent(originalContent string, patch string) (string, error) {
	origLines := strings.Split(strings.ReplaceAll(originalContent, "\r\n", "\n"), "\n")
	hasTrailingNewline := strings.HasSuffix(originalContent, "\n")
	if len(origLines) > 0 && origLines[len(origLines)-1] == "" && hasTrailingNewline {
		origLines = origLines[:len(origLines)-1]
	}
	if originalContent == "" {
		origLines = []string{}
	}

	patchLines := strings.Split(strings.ReplaceAll(patch, "\r\n", "\n"), "\n")
	if len(patchLines) > 0 && patchLines[len(patchLines)-1] == "" {
		patchLines = patchLines[:len(patchLines)-1]
	}

	var result []string
	origIdx := 0 // 0-based index in origLines

	for i := 0; i < len(patchLines); i++ {
		line := patchLines[i]
		if !strings.HasPrefix(line, "@@ ") {
			continue
		}

		matches := hunkHeaderPattern.FindStringSubmatch(line)
		if matches == nil {
			return "", fmt.Errorf("malformed hunk header: %q", line)
		}

		oldStart, err := strconv.Atoi(matches[1])
		if err != nil || oldStart < 0 {
			return "", fmt.Errorf("invalid hunk start line: %d", oldStart)
		}

		targetOrigIdx := 0
		if oldStart > 0 {
			targetOrigIdx = oldStart - 1
		}
		// Copy unmodified lines up to targetOrigIdx
		for origIdx < targetOrigIdx && origIdx < len(origLines) {
			result = append(result, origLines[origIdx])
			origIdx++
		}

		// Apply the hunk lines
		for i++; i < len(patchLines); i++ {
			hLine := patchLines[i]
			if strings.HasPrefix(hLine, "@@ ") || strings.HasPrefix(hLine, "diff --git ") {
				i-- // step back for outer loop
				break
			}
			if len(hLine) == 0 {
				// Empty line in hunk treated as empty context line
				if origIdx < len(origLines) && origLines[origIdx] == "" {
					result = append(result, "")
					origIdx++
				} else {
					return "", fmt.Errorf("hunk context mismatch at line %d: expected empty line", origIdx+1)
				}
				continue
			}

			prefix := hLine[0]
			content := hLine[1:]

			switch prefix {
			case ' ':
				if origIdx >= len(origLines) || origLines[origIdx] != content {
					var got string
					if origIdx < len(origLines) {
						got = origLines[origIdx]
					} else {
						got = "<EOF>"
					}
					return "", fmt.Errorf("hunk context mismatch at line %d: want %q, got %q", origIdx+1, content, got)
				}
				result = append(result, origLines[origIdx])
				origIdx++
			case '-':
				if origIdx >= len(origLines) || origLines[origIdx] != content {
					var got string
					if origIdx < len(origLines) {
						got = origLines[origIdx]
					} else {
						got = "<EOF>"
					}
					return "", fmt.Errorf("hunk deletion mismatch at line %d: want %q, got %q", origIdx+1, content, got)
				}
				origIdx++
			case '+':
				result = append(result, content)
			case '\\':
				// \ No newline at end of file
				continue
			default:
				return "", fmt.Errorf("unexpected patch line prefix %q in hunk", string(prefix))
			}
		}
	}

	// Copy remaining unmodified lines
	for origIdx < len(origLines) {
		result = append(result, origLines[origIdx])
		origIdx++
	}

	res := strings.Join(result, "\n")
	hasNoNewline := strings.Contains(patch, "\\ No newline at end of file")
	if !hasNoNewline && (hasTrailingNewline || originalContent == "") {
		res += "\n"
	}
	return res, nil
}
