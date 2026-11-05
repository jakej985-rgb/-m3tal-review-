package review

import (
	"regexp"
	"strconv"

	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
)

// CryptoRule flags weak primitives: broken hashes/ciphers and
// non-cryptographic randomness used for security-sensitive values.
type CryptoRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (CryptoRule) Name() string {
	return "weak-cryptography"
}

var weakPrimitivePatterns = []struct {
	language language.CodeLanguage
	pattern  *regexp.Regexp
	severity string
	message  string
}{
	{
		language: language.LanguageGo,
		pattern:  regexp.MustCompile(`\b(?:md5|sha1)\.[A-Z]\w*`),
		severity: "low",
		message:  "Weak hash algorithm (MD5 or SHA-1); do not use it for security purposes",
	},
	{
		language: language.LanguageGo,
		pattern:  regexp.MustCompile(`\b(?:des|rc4)\.[A-Z]\w*`),
		severity: "medium",
		message:  "Broken cipher (DES or RC4); use AES-GCM or ChaCha20-Poly1305",
	},
	{
		language: language.LanguageGo,
		pattern: regexp.MustCompile(
			`(?i)\b\w*(?:token|secret|password|passwd|nonce|salt|session\w*|apikey|api_key|privatekey|csrf)\w*` +
				`\s*:?=\s*[^\n]{0,120}?\brand\.(?:Int\d*n?|Uint\d+|Float64|Perm|Shuffle|New)\s*\(`),
		severity: "high",
		message:  "Security-sensitive value generated with math/rand; use crypto/rand",
	},
	{
		language: language.LanguagePython,
		pattern: regexp.MustCompile(
			`(?i)\b\w*(?:token|secret|password|passwd|nonce|salt|session\w*|apikey|api_key)\w*` +
				`\s*=\s*[^\n]{0,120}?\brandom\.(?:choice|choices|randint|randrange|random|randbytes|sample|shuffle|getrandbits)\s*\(`),
		severity: "high",
		message:  "Security-sensitive value generated with the random module; use secrets",
	},
	{
		language: language.LanguagePython,
		pattern:  regexp.MustCompile(`\brandom\.(?:token_hex|token_urlsafe)\s*\(`),
		severity: "high",
		message:  "random.token_hex/token_urlsafe is not cryptographically secure; use secrets.token_hex/token_urlsafe",
	},
	{
		language: language.LanguageJavaScript,
		pattern: regexp.MustCompile(
			`(?i)\b\w*(?:token|secret|password|passwd|nonce|salt|session\w*|apikey|api_key)\w*` +
				`[^\n]{0,120}?Math\.random\s*\(`),
		severity: "high",
		message:  "Security-sensitive value generated with Math.random(); use crypto.randomBytes/randomUUID",
	},
	{
		language: language.LanguageTypeScript,
		pattern: regexp.MustCompile(
			`(?i)\b\w*(?:token|secret|password|passwd|nonce|salt|session\w*|apikey|api_key)\w*` +
				`[^\n]{0,120}?Math\.random\s*\(`),
		severity: "high",
		message:  "Security-sensitive value generated with Math.random(); use crypto.randomBytes/randomUUID",
	},
}

func (r CryptoRule) Check(diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		fileLanguage := (language.CodeChecker{}).Language(block.file)
		code := string(maskNonCode(block.file, block.text))
		for _, weakPattern := range weakPrimitivePatterns {
			if weakPattern.language != fileLanguage {
				continue
			}
			for _, match := range weakPattern.pattern.FindAllStringIndex(code, -1) {
				if !matchTouchesAdded(block, code, match[0], match[1]) {
					continue
				}
				line := lineAtOffset(block.firstLine, code, match[0])
				key := block.file + ":" + strconv.Itoa(line)
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, Finding{
					Rule:        "weak-cryptography",
					Severity:    weakPattern.severity,
					File:        block.file,
					Line:        line,
					Message:     weakPattern.message,
					Remediation: "Use a cryptographically secure primitive for security-sensitive operations.",
				})
			}
		}
	}
	return findings
}
