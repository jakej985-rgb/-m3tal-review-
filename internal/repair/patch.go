package repair

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
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
	if newContent != p.ProposedContent {
		return fmt.Errorf("applied content for %q does not match verified proposal content", targetPath)
	}

	// Preserve the existing file's permission bits; new files get 0644.
	perm := os.FileMode(0644)
	if info, statErr := os.Stat(targetPath); statErr == nil {
		perm = info.Mode().Perm()
	}

	// Ensure parent directories exist
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return fmt.Errorf("create parent directory for %q: %w", targetPath, err)
	}

	return writeFileAtomic(targetPath, []byte(newContent), perm)
}

// writeFileAtomic writes content to path via a temporary file in the same
// directory, fsync, and rename so readers never observe a partial write.
func writeFileAtomic(path string, content []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".m3tal-repair-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temporary file: %w", err)
	}
	if _, err := tmp.Write(content); err != nil {
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	// Windows denies renaming over an existing destination that is momentarily
	// open, so retry transient failures there.
	var renameErr error
	attempts := 1
	if runtime.GOOS == "windows" {
		attempts = 20
	}
	for i := 0; i < attempts; i++ {
		renameErr = os.Rename(tmpPath, path)
		if renameErr == nil {
			break
		}
		if runtime.GOOS == "windows" {
			time.Sleep(time.Duration(i+1) * 10 * time.Millisecond)
		} else {
			break
		}
	}
	if renameErr != nil {
		return fmt.Errorf("rename temporary file to %q: %w", path, renameErr)
	}
	cleanup = false
	return nil
}

// ApplyProposalToContent applies a Proposal to original content.
//
// The proposal is only applied verbatim when the current content matches
// OriginalContent exactly (an empty OriginalContent matches only an empty
// file — it is not a wildcard). Otherwise the patch is applied and the
// result must equal ProposedContent, so a patch/content mismatch is
// always an error rather than silently divergent output.
func ApplyProposalToContent(originalContent string, p *Proposal) (string, error) {
	if p.ProposedContent != "" && p.OriginalContent == originalContent {
		return p.ProposedContent, nil
	}
	patched, err := ApplyPatchToContent(originalContent, p.Patch)
	if err != nil {
		return "", err
	}
	if patched != p.ProposedContent {
		return "", fmt.Errorf("patch result does not match proposal proposed_content")
	}
	return patched, nil
}

// patchItem is one parsed line inside a hunk body.
type patchItem struct {
	kind byte // ' ', '-', '+', or '\\'
	text string
}

// ApplyPatchToContent applies a unified diff patch to original text.
//
// Lines are compared without their '\n' terminator but '\r' is preserved,
// so CRLF files round-trip byte-identically. Hunk bodies must satisfy
// their declared old/new line counts (matching ValidatePatch), and
// "\ No newline at end of file" markers are honored per-side: a marker
// after '-', ' ', or '+' asserts that the referenced file's last line has
// no trailing newline and is only legal at end of file.
func ApplyPatchToContent(originalContent string, patch string) (string, error) {
	origLines := splitFileLines(originalContent)

	// Do NOT normalize \r\n here: a trailing '\r' on a patch line is file
	// content for CRLF sources and must be preserved for round-trips.
	patchLines := strings.Split(patch, "\n")
	if len(patchLines) > 0 && patchLines[len(patchLines)-1] == "" {
		patchLines = patchLines[:len(patchLines)-1]
	}

	var result strings.Builder
	origIdx := 0        // index into origLines; elements retain their '\n' terminator
	noNLResultLen := -1 // result length at the first '+'/' ' line marked no-newline

	copyThrough := func(target int) {
		for origIdx < target && origIdx < len(origLines) {
			result.WriteString(origLines[origIdx])
			origIdx++
		}
	}

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
		declOld, declNew := hunkCount(matches[2]), hunkCount(matches[4])

		targetOrigIdx := 0
		if oldStart > 0 {
			targetOrigIdx = oldStart - 1
		}
		copyThrough(targetOrigIdx)

		// Collect this hunk's body items.
		var items []patchItem
		for i++; i < len(patchLines); i++ {
			hLine := patchLines[i]
			if strings.HasPrefix(hLine, "@@ ") || strings.HasPrefix(hLine, "diff --git ") {
				i--
				break
			}
			if hLine == "" {
				// Bare empty line: unified diffs encode an empty context
				// line as a single space, but tolerate the bare form.
				items = append(items, patchItem{kind: ' ', text: ""})
				continue
			}
			items = append(items, patchItem{kind: hLine[0], text: hLine[1:]})
		}

		// Verify declared counts before applying.
		var oldSeen, newSeen int
		for _, it := range items {
			switch it.kind {
			case ' ', '-':
				oldSeen++
			}
			if it.kind == ' ' || it.kind == '+' {
				newSeen++
			}
		}
		if oldSeen != declOld || newSeen != declNew {
			return "", fmt.Errorf("hunk line count mismatch: declared -%d +%d, got -%d +%d", declOld, declNew, oldSeen, newSeen)
		}

		for j := 0; j < len(items); j++ {
			it := items[j]
			switch it.kind {
			case ' ':
				if origIdx >= len(origLines) || lineBody(origLines[origIdx]) != it.text {
					return "", hunkMismatch("context", origIdx, origLines, it.text)
				}
				result.WriteString(origLines[origIdx])
				origIdx++
			case '-':
				if origIdx >= len(origLines) || lineBody(origLines[origIdx]) != it.text {
					return "", hunkMismatch("deletion", origIdx, origLines, it.text)
				}
				origIdx++
			case '+':
				// A following "\ No newline" marker suppresses the
				// terminator for this line.
				noNL := j+1 < len(items) && items[j+1].kind == '\\'
				result.WriteString(it.text)
				if !noNL {
					result.WriteByte('\n')
				} else if noNLResultLen < 0 {
					noNLResultLen = result.Len()
				}
			case '\\':
				if j == 0 {
					return "", fmt.Errorf("newline marker without preceding hunk line")
				}
				prev := items[j-1]
				// The marker asserts the referenced side's file ends
				// without a newline at this line.
				switch prev.kind {
				case '-':
					if origIdx != len(origLines) || strings.HasSuffix(origLines[origIdx-1], "\n") {
						return "", fmt.Errorf("newline marker claims old file lacks trailing newline, but it is not at end of file")
					}
				case '+':
					// '+' already wrote without '\n' via lookahead.
				case ' ':
					if origIdx != len(origLines) || strings.HasSuffix(origLines[origIdx-1], "\n") {
						return "", fmt.Errorf("newline marker claims old file lacks trailing newline, but it is not at end of file")
					}
					if noNLResultLen < 0 {
						noNLResultLen = result.Len()
					}
				default:
					return "", fmt.Errorf("newline marker after invalid hunk line %q", string(prev.kind))
				}
			default:
				return "", fmt.Errorf("unexpected patch line prefix %q in hunk", string(it.kind))
			}
		}
	}

	// Copy remaining unmodified lines
	for origIdx < len(origLines) {
		result.WriteString(origLines[origIdx])
		origIdx++
	}

	if noNLResultLen >= 0 && result.Len() != noNLResultLen {
		return "", fmt.Errorf("newline marker is not at end of file")
	}
	return result.String(), nil
}

func hunkCount(s string) int {
	if s == "" {
		return 1
	}
	n, _ := strconv.Atoi(s)
	return n
}

func hunkMismatch(kind string, idx int, origLines []string, want string) error {
	var got string
	if idx < len(origLines) {
		got = lineBody(origLines[idx])
	} else {
		got = "<EOF>"
	}
	return fmt.Errorf("hunk %s mismatch at line %d: want %q, got %q", kind, idx+1, want, got)
}
