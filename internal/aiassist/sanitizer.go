// Package aiassist provides context sanitization and prompt injection defense.
package aiassist

import (
	"regexp"
	"strings"
)

var (
	bearerTokenRe = regexp.MustCompile(`(?i)\b(?:bearer\s+[a-zA-Z0-9_\-\.]{16,})\b`)
	kvCredRe      = regexp.MustCompile(`(?i)(?:password|token|passwd)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{12,})["']?`)
	awsKeyRe      = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	jwtTokenRe    = regexp.MustCompile(`\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b`)

	injectionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:ignore\s+(?:all\s+)?previous\s+instructions)`),
		regexp.MustCompile(`(?i)(?:you\s+are\s+now\s+(?:in\s+)?developer\s+mode)`),
		regexp.MustCompile(`(?i)(?:system\s*:\s*override\s+policy)`),
		regexp.MustCompile(`(?:<\|im_start\|>|<\|im_end\|>)`),
		regexp.MustCompile(`(?i)(?:disregard\s+(?:the\s+)?above\s+prompt)`),
	}
)

// RedactSecrets scans text and replaces sensitive credentials with safe placeholders.
func RedactSecrets(text string) (string, []RedactionRecord) {
	var records []RedactionRecord
	sanitized := text

	if locs := awsKeyRe.FindAllStringIndex(sanitized, -1); len(locs) > 0 {
		for _, loc := range locs {
			records = append(records, RedactionRecord{Kind: "aws_access_key", Offset: loc[0]})
		}
		sanitized = awsKeyRe.ReplaceAllString(sanitized, "AKIA[REDACTED_ACCESS_KEY]")
	}

	if locs := jwtTokenRe.FindAllStringIndex(sanitized, -1); len(locs) > 0 {
		for _, loc := range locs {
			records = append(records, RedactionRecord{Kind: "jwt_token", Offset: loc[0]})
		}
		sanitized = jwtTokenRe.ReplaceAllString(sanitized, "[REDACTED_JWT_TOKEN]")
	}

	if locs := bearerTokenRe.FindAllStringIndex(sanitized, -1); len(locs) > 0 {
		for _, loc := range locs {
			records = append(records, RedactionRecord{Kind: "bearer_token", Offset: loc[0]})
		}
		sanitized = bearerTokenRe.ReplaceAllString(sanitized, "Bearer [REDACTED_TOKEN]")
	}

	if matches := kvCredRe.FindAllStringSubmatchIndex(sanitized, -1); len(matches) > 0 {
		for _, m := range matches {
			if len(m) >= 4 && m[2] >= 0 {
				records = append(records, RedactionRecord{Kind: "secret_assignment", Offset: m[2]})
			}
		}
		sanitized = kvCredRe.ReplaceAllString(sanitized, "secret=[REDACTED]")
	}

	return sanitized, records
}

// DefangPromptInjection detects and neutralizes known adversarial prompt injection phrases.
func DefangPromptInjection(text string) string {
	res := text
	for _, p := range injectionPatterns {
		res = p.ReplaceAllString(res, "[DEFANGED_INSTRUCTION]")
	}
	return res
}

// WrapUntrustedContent encloses repository diff or file contents in clear delimiter boundaries.
func WrapUntrustedContent(content string, maxBytes int) (string, []RedactionRecord) {
	redacted, records := RedactSecrets(content)
	defanged := DefangPromptInjection(redacted)

	if maxBytes > 0 && len(defanged) > maxBytes {
		defanged = defanged[:maxBytes] + "\n... [TRUNCATED_TO_BUDGET]"
	}

	var sb strings.Builder
	sb.WriteString("<<<UNTRUSTED_REPOSITORY_CONTENT_START>>>\n")
	sb.WriteString(defanged)
	sb.WriteString("\n<<<UNTRUSTED_REPOSITORY_CONTENT_END>>>")
	return sb.String(), records
}
