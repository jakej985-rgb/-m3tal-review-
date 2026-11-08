package repair

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const MaxPatchSize = 10 << 20 // 10 MiB limit

var (
	hunkHeaderPattern = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)
)

// ValidatePatchBoundaries validates that:
// 1. targetFile is a safe, relative path within repoRoot with no traversal or symlink escapes.
// 2. patch is non-empty, bounded in size, syntactically valid unified diff.
// 3. all file headers in patch target strictly targetFile and contain no directory traversal.
// 4. hunks are well-formed with matching line counts.
func ValidatePatchBoundaries(repoRoot, targetFile, patch string) error {
	if err := ValidateTargetFilePath(repoRoot, targetFile); err != nil {
		return fmt.Errorf("target file path validation failed: %w", err)
	}

	if err := ValidatePatch(patch, targetFile); err != nil {
		return fmt.Errorf("patch validation failed: %w", err)
	}

	return nil
}

// ValidateTargetFilePath ensures the target path is strictly inside repoRoot and free from directory traversal.
func ValidateTargetFilePath(repoRoot, targetFile string) error {
	if strings.TrimSpace(targetFile) == "" {
		return errors.New("target file path cannot be empty")
	}

	// Reject absolute paths
	if filepath.IsAbs(targetFile) || strings.HasPrefix(targetFile, "/") || strings.HasPrefix(targetFile, "\\") {
		return fmt.Errorf("absolute path not allowed: %q", targetFile)
	}

	// Enforce clean path without directory traversal
	normTarget := filepath.ToSlash(targetFile)
	cleaned := filepath.ToSlash(filepath.Clean(targetFile))
	if cleaned != normTarget && filepath.Clean(targetFile) != targetFile {
		return fmt.Errorf("path is not canonical/clean (%q vs %q)", targetFile, cleaned)
	}

	if !filepath.IsLocal(normTarget) || normTarget == "." || strings.HasPrefix(normTarget, "..") || strings.Contains(targetFile, "\\") {
		return fmt.Errorf("path traversal attempt in target path: %q", targetFile)
	}

	// Verify against absolute repository root
	if repoRoot != "" {
		absRoot, err := filepath.Abs(repoRoot)
		if err != nil {
			return fmt.Errorf("resolve repository root: %w", err)
		}

		fullTarget := filepath.Join(absRoot, targetFile)
		rel, err := filepath.Rel(absRoot, fullTarget)
		if err != nil || !filepath.IsLocal(rel) || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("target file escapes repository root: %q", targetFile)
		}

		// Inspect path components for symlink traversal
		current := absRoot
		parts := strings.Split(rel, string(filepath.Separator))
		for i, part := range parts {
			current = filepath.Join(current, part)
			info, err := os.Lstat(current)
			if os.IsNotExist(err) {
				break
			}
			if err != nil {
				return fmt.Errorf("inspect path component %q: %w", current, err)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				// Evaluate symlink destination to guarantee it does not escape repo root
				targetResolved, err := filepath.EvalSymlinks(current)
				if err != nil {
					return fmt.Errorf("resolve symlink %q: %w", current, err)
				}
				resolvedRel, err := filepath.Rel(absRoot, targetResolved)
				if err != nil || !filepath.IsLocal(resolvedRel) || strings.HasPrefix(resolvedRel, "..") {
					return fmt.Errorf("symlink %q escapes repository root (points to %q)", current, targetResolved)
				}
			}
			if i < len(parts)-1 && !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
				return fmt.Errorf("path component %q is not a directory", current)
			}
		}
	}

	return nil
}

// ValidatePatch verifies the unified diff format, bounded size, and consistency with targetFile.
func ValidatePatch(patch, expectedTargetFile string) error {
	if strings.TrimSpace(patch) == "" {
		return errors.New("patch content cannot be empty")
	}

	if len(patch) > MaxPatchSize {
		return fmt.Errorf("patch exceeds maximum allowed size (%d bytes > %d limit)", len(patch), MaxPatchSize)
	}

	lines := strings.Split(strings.ReplaceAll(patch, "\r\n", "\n"), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	var oldFile, newFile string
	hunkCount := 0
	inHunk := false
	var expectedOldCount, expectedNewCount int
	var actualOldCount, actualNewCount int
	lastOldEnd := -1

	normExpected := filepath.ToSlash(filepath.Clean(expectedTargetFile))

	for lineIdx, line := range lines {
		if strings.HasPrefix(line, "diff --git ") {
			continue
		}
		if strings.HasPrefix(line, "index ") || strings.HasPrefix(line, "new file mode ") || strings.HasPrefix(line, "deleted file mode ") {
			continue
		}

		if strings.HasPrefix(line, "--- ") {
			oldFile = extractPathFromHeader(line)
			if err := checkHeaderPathSafety(oldFile, normExpected); err != nil {
				return fmt.Errorf("invalid '---' header on line %d: %w", lineIdx+1, err)
			}
			continue
		}

		if strings.HasPrefix(line, "+++ ") {
			newFile = extractPathFromHeader(line)
			if err := checkHeaderPathSafety(newFile, normExpected); err != nil {
				return fmt.Errorf("invalid '+++' header on line %d: %w", lineIdx+1, err)
			}
			continue
		}

		if strings.HasPrefix(line, "@@ ") {
			// If already in a hunk, verify the previous hunk line counts
			if inHunk {
				if actualOldCount != expectedOldCount || actualNewCount != expectedNewCount {
					return fmt.Errorf("malformed hunk before line %d: line counts mismatch (old: got %d want %d; new: got %d want %d)",
						lineIdx+1, actualOldCount, expectedOldCount, actualNewCount, expectedNewCount)
				}
			}

			matches := hunkHeaderPattern.FindStringSubmatch(line)
			if matches == nil {
				return fmt.Errorf("malformed hunk header on line %d: %q", lineIdx+1, line)
			}

			// Parse expected counts
			expectedOldCount = 1
			if matches[2] != "" {
				expectedOldCount, _ = strconv.Atoi(matches[2])
			}
			expectedNewCount = 1
			if matches[4] != "" {
				expectedNewCount, _ = strconv.Atoi(matches[4])
			}

			oldStart, _ := strconv.Atoi(matches[1])
			if hunkCount > 0 && lastOldEnd >= 0 && oldStart < lastOldEnd {
				return fmt.Errorf("malformed patch on line %d: hunk start line %d is out of order or overlaps previous hunk ending at line %d",
					lineIdx+1, oldStart, lastOldEnd)
			}
			lastOldEnd = oldStart + expectedOldCount

			actualOldCount = 0
			actualNewCount = 0
			inHunk = true
			hunkCount++
			continue
		}

		if inHunk {
			if len(line) == 0 {
				// Empty line in hunk treated as empty context line
				actualOldCount++
				actualNewCount++
				continue
			}

			switch line[0] {
			case ' ':
				actualOldCount++
				actualNewCount++
			case '-':
				actualOldCount++
			case '+':
				actualNewCount++
			case '\\':
				// \ No newline at end of file
				continue
			default:
				return fmt.Errorf("malformed patch line on line %d: unexpected line prefix %q", lineIdx+1, string(line[0]))
			}
		}
	}

	if inHunk {
		if actualOldCount != expectedOldCount || actualNewCount != expectedNewCount {
			return fmt.Errorf("malformed final hunk: line counts mismatch (old: got %d want %d; new: got %d want %d)",
				actualOldCount, expectedOldCount, actualNewCount, expectedNewCount)
		}
	}

	if hunkCount == 0 {
		return errors.New("malformed patch: no valid @@ hunks found")
	}

	return nil
}

func extractPathFromHeader(header string) string {
	var raw string
	if strings.HasPrefix(header, "--- ") {
		raw = strings.TrimPrefix(header, "--- ")
	} else if strings.HasPrefix(header, "+++ ") {
		raw = strings.TrimPrefix(header, "+++ ")
	} else {
		return ""
	}
	raw = strings.TrimSpace(raw)
	// If followed by tab (timestamp / metadata), strip tab and anything after
	if idx := strings.IndexByte(raw, '\t'); idx != -1 {
		raw = raw[:idx]
	}
	raw = strings.TrimSpace(raw)
	// If enclosed in quotes, unquote
	if strings.HasPrefix(raw, "\"") && strings.HasSuffix(raw, "\"") {
		if unquoted, err := strconv.Unquote(raw); err == nil {
			raw = unquoted
		} else {
			raw = strings.Trim(raw, "\"")
		}
	}
	raw = strings.TrimPrefix(raw, "a/")
	raw = strings.TrimPrefix(raw, "b/")
	return raw
}

func checkHeaderPathSafety(path, expectedTarget string) error {
	if path == "/dev/null" {
		return nil
	}
	if path == "" {
		return errors.New("missing path in header")
	}
	if filepath.IsAbs(path) || strings.HasPrefix(path, "/") || strings.HasPrefix(path, "\\") {
		return fmt.Errorf("absolute path traversal detected in patch header: %q", path)
	}
	normPath := filepath.ToSlash(filepath.Clean(path))
	if !filepath.IsLocal(normPath) || strings.HasPrefix(normPath, "..") {
		return fmt.Errorf("path traversal detected in patch header: %q", path)
	}
	if expectedTarget != "" && normPath != expectedTarget {
		return fmt.Errorf("patch header path %q does not match expected target file %q", normPath, expectedTarget)
	}
	return nil
}
