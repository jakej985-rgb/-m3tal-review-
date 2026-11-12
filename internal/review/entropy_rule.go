package review

import (
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// EntropyRule detects high-entropy strings (tokens, private keys, passwords)
// that may be credentials not caught by fixed regex patterns.
// It is guarded by character set distributions (Hex, Base64, Base58), length gates,
// context sensitivity, and word exclusion lists to minimize false positives.
type EntropyRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (EntropyRule) Name() string {
	return "high-entropy-secret"
}

// ShannonEntropy calculates the Shannon entropy in bits per character:
// H(S) = - sum(p * log2(p))
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	length := float64(len(s))
	var entropy float64
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

var (
	// contextSecretRe checks for secret-suggestive words near assignments or definitions.
	contextSecretRe = regexp.MustCompile(`(?i)(secret|token|password|passwd|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|privkey|client[_-]?secret|signing[_-]?key|bearer|credential|ssh[_-]?key|encryption[_-]?key|passphrase|app[_-]?secret|webhook[_-]?secret|jwt[_-]?secret|session[_-]?secret)`)

	// uuidPattern matches standard UUIDs which are high-entropy but not secrets.
	uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

	// candidateStringPattern matches quoted strings or assignments in untrusted content.
	candidateStringPattern = regexp.MustCompile(`"([^"\r\n\\]{16,512})"` +
		`|'([^'\r\n\\]{16,512})'` +
		"|`([^`\r\n\\\\]{16,512})`" +
		`|(?m)(?:^|[ \t]+)(?:export[ \t]+)?[A-Za-z0-9_.-]+[ \t]*[:=][ \t]*([^\s"'\r\n;]{16,512})`)
)

var entropyPlaceholderWords = []string{
	"example", "sample", "dummy", "fake", "test", "your_", "changeme",
	"placeholder", "redacted", "xxxxx", "notreal", "not-a-real", "mock",
	"template", "default", "foobar",
}

func isSensitiveFile(filePath string) bool {
	base := strings.ToLower(filepath.Base(filePath))
	if strings.HasPrefix(base, ".env") || base == ".netrc" {
		return true
	}
	ext := strings.ToLower(filepath.Ext(base))
	switch ext {
	case ".conf", ".config", ".json", ".yaml", ".yml", ".toml", ".ini", ".properties":
		return true
	default:
		return false
	}
}

// CharsetType represents the classified character set of a high-entropy string candidate.
type CharsetType string

const (
	CharsetHex    CharsetType = "hex"
	CharsetBase58 CharsetType = "base58"
	CharsetBase64 CharsetType = "base64"
	CharsetAscii  CharsetType = "ascii"
	CharsetNone   CharsetType = "none"
)

// classifyCharset checks the predominant character set and character distribution.
func classifyCharset(s string) (CharsetType, int) {
	var isHexOnly, isBase58Only, isBase64Only = true, true, true
	distinct := make(map[rune]bool)
	hasLower, hasUpper, hasDigit, hasSpecial := false, false, false, false

	for _, r := range s {
		distinct[r] = true
		if r > 127 {
			return CharsetNone, 0
		}
		ch := byte(r)
		isHexChar := (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
		if !isHexChar {
			isHexOnly = false
		}

		isB58Char := (ch >= '1' && ch <= '9') || (ch >= 'a' && ch <= 'k') || (ch >= 'm' && ch <= 'z') || (ch >= 'A' && ch <= 'H') || (ch >= 'J' && ch <= 'N') || (ch >= 'P' && ch <= 'Z')
		if !isB58Char {
			isBase58Only = false
		}

		isB64Char := (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '+' || ch == '/' || ch == '=' || ch == '-' || ch == '_'
		if !isB64Char {
			isBase64Only = false
		}

		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSpecial = true
		}
	}

	classCount := 0
	if hasLower {
		classCount++
	}
	if hasUpper {
		classCount++
	}
	if hasDigit {
		classCount++
	}
	if hasSpecial {
		classCount++
	}

	distCount := len(distinct)
	if isHexOnly {
		return CharsetHex, distCount
	}
	if isBase58Only && classCount >= 2 {
		return CharsetBase58, distCount
	}
	if isBase64Only && classCount >= 2 {
		return CharsetBase64, distCount
	}
	if classCount >= 3 {
		return CharsetAscii, distCount
	}
	return CharsetNone, distCount
}

func looksLikePlaceholderEntropy(token string) bool {
	lower := strings.ToLower(token)
	for _, word := range entropyPlaceholderWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

// isGeneratedDataFile reports whether the path is a lockfile, checksum
// manifest, or generated artifact whose high-entropy strings are hashes,
// digests, or package integrity values rather than credentials.
func isGeneratedDataFile(filePath string) bool {
	base := strings.ToLower(filepath.Base(filePath))
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
		"go.sum", "cargo.lock", "gemfile.lock", "composer.lock", "poetry.lock",
		"pubspec.lock", "packages.lock.json", "flake.lock":
		return true
	}
	if strings.HasSuffix(base, ".sum") || strings.HasSuffix(base, ".lock") ||
		strings.HasSuffix(base, ".min.js") || strings.HasSuffix(base, ".min.css") {
		return true
	}
	// Docs and CI workflows: high-entropy strings there are overwhelmingly
	// hashes, SHAs, and checksums; real credential formats are still caught by
	// the dedicated secret rules.
	ext := strings.ToLower(filepath.Ext(base))
	if ext == ".md" || ext == ".markdown" || ext == ".rst" || ext == ".mdx" {
		return true
	}
	slashPath := "/" + strings.TrimPrefix(filepath.ToSlash(filePath), "/")
	if strings.Contains(slashPath, "/docs/") || strings.Contains(slashPath, "/.github/workflows/") {
		return true
	}
	// Package manager artifact directories (e.g. dists/, vendor bundles)
	return strings.Contains(slashPath, "/dists/") ||
		strings.Contains(slashPath, "/vendor/")
}

func isCommonNonSecret(token string) bool {
	if uuidPattern.MatchString(token) {
		return true
	}
	// Email addresses and URLs are high-entropy but not credentials.
	if strings.Contains(token, "@") && strings.Contains(token, ".") {
		return true
	}
	// Bot/no-reply emails such as 123+github-actions[bot]@users.noreply.github.com
	if strings.Contains(token, "[bot]") || strings.Contains(token, "noreply") {
		return true
	}
	if strings.HasPrefix(token, "http://") || strings.HasPrefix(token, "https://") || strings.HasPrefix(token, "git@") {
		return true
	}
	if strings.HasPrefix(token, "data:image/") || strings.HasPrefix(token, "sha256-") || strings.HasPrefix(token, "sha384-") || strings.HasPrefix(token, "sha512-") {
		return true
	}
	if strings.Contains(token, " ") || strings.Contains(token, "\t") {
		return true
	}
	// Common file or import path indicators
	if strings.Count(token, "/") >= 2 || strings.Count(token, "\\") >= 2 {
		return true
	}
	return false
}

func (r EntropyRule) Check(diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		if isGeneratedDataFile(block.file) || isTestSourceFile(block.file) {
			continue
		}
		// Limit block scanning if excessively large to protect against untrusted hostile diffs
		lines := strings.Split(block.text, "\n")
		offset := 0

		for lineIdx, lineText := range lines {
			lineNum := block.firstLine + lineIdx
			currentOffset := offset
			offset += len(lineText) + 1 // +1 for \n

			// Bounded scan per line: ignore lines longer than 4096 bytes (e.g. minified assets)
			if len(lineText) > 4096 || len(lineText) < 16 {
				continue
			}

			// Don't flag secrets inside comment lines
			trimmed := strings.TrimSpace(lineText)
			isEnv := strings.HasPrefix(filepath.Base(block.file), ".env")
			if !isEnv && (strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "#")) {
				continue
			}

			// Check if line touches added lines
			if !block.addedLines[lineNum] {
				continue
			}

			isSensitive := isSensitiveFile(block.file)
			hasSecretContext := contextSecretRe.MatchString(lineText)

			// If neither sensitive file nor secret context, skip line to minimize false positives
			if !isSensitive && !hasSecretContext {
				continue
			}

			matches := candidateStringPattern.FindAllStringSubmatchIndex(lineText, -1)
			for _, match := range matches {
				var tokenStart, tokenEnd int
				for i := 1; i <= 4; i++ {
					if match[i*2] >= 0 && match[i*2+1] > match[i*2] {
						tokenStart = match[i*2]
						tokenEnd = match[i*2+1]
						break
					}
				}
				if tokenEnd <= tokenStart {
					continue
				}

				if offsetInComment(block.file, block.text, currentOffset+tokenStart) {
					continue
				}

				token := lineText[tokenStart:tokenEnd]
				if len(token) < 20 && !(len(token) >= 16 && hasSecretContext) {
					continue
				}
				if looksLikePlaceholderEntropy(token) || isCommonNonSecret(token) {
					continue
				}

				charset, distinctCount := classifyCharset(token)
				if charset == CharsetNone {
					continue
				}

				entropy := ShannonEntropy(token)
				isHighEntropy := false

				switch charset {
				case CharsetHex:
					// Hex max entropy is 4.0; require at least 32 chars and >= 3.0 entropy with >= 10 distinct chars
					// Or 24 chars if strongly in secret context with >= 3.2 entropy
					if len(token) >= 32 && entropy >= 3.0 && distinctCount >= 10 {
						isHighEntropy = true
					} else if len(token) >= 24 && hasSecretContext && entropy >= 3.2 && distinctCount >= 9 {
						isHighEntropy = true
					}
				case CharsetBase58:
					// Base58 max entropy ~5.86; require >= 20 chars and >= 4.2 entropy with >= 12 distinct chars
					if len(token) >= 20 && entropy >= 4.2 && distinctCount >= 12 {
						isHighEntropy = true
					}
				case CharsetBase64:
					// Base64 max entropy 6.0; require >= 20 chars and >= 4.4 entropy with >= 12 distinct chars
					if len(token) >= 20 && entropy >= 4.4 && distinctCount >= 12 {
						isHighEntropy = true
					}
				case CharsetAscii:
					// Mixed ascii printable; require >= 20 chars and >= 4.5 entropy with >= 14 distinct chars
					if len(token) >= 20 && entropy >= 4.5 && distinctCount >= 14 {
						isHighEntropy = true
					}
				}

				if !isHighEntropy {
					continue
				}

				key := block.file + ":" + strconv.Itoa(lineNum)
				if seen[key] {
					continue
				}
				seen[key] = true

				findings = append(findings, Finding{
					Category:    "security",
					Rule:        "high-entropy-secret",
					Severity:    "high",
					File:        block.file,
					Line:        lineNum,
					Message:     fmt.Sprintf("High-entropy string detected in secret context (%s, entropy: %.2f)", charset, entropy),
					Remediation: "Store credentials and private keys in a secrets manager or environment variables, not in source code.",
				})
			}
		}
	}

	return findings
}
