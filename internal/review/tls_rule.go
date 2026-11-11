package review

import (
	"go/scanner"
	"go/token"
	"path"
	"regexp"
	"strings"
)

type TLSRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (TLSRule) Name() string {
	return "insecure-tls-verification"
}

func (r TLSRule) Check(diff string) []Finding {
	var findings []Finding
	for _, fileDiff := range ParseDiff(diff) {
		if !strings.EqualFold(path.Ext(fileDiff.Path), ".go") {
			continue
		}
		// Performance optimization: Generate diff source blocks directly from fileDiff
		// instead of re-parsing the entire diff and scanning for fileDiff.Path.
		blocks := fileDiffSourceBlocks(fileDiff)
		if source, err := readRuleSource(r.RepositoryRoot, fileDiff.Path, r.WorkingTree); err == nil {
			blocks = []diffSourceBlock{fullSourceBlock(fileDiff.Path, source, fileDiff.AddedLines)}
		}
		for _, block := range blocks {
			severity, message := tlsSeverityForBlock(block)
			for _, line := range insecureTLSLines(block.text) {
				if !block.addedLines[line] {
					continue
				}
				findings = append(findings, Finding{Rule: "insecure-tls-verification", Severity: severity, File: block.file, Line: line, Message: message, Remediation: "Remove InsecureSkipVerify or set it to false to ensure secure connections; when pinning is intentional, verify the peer certificate explicitly."})
			}
		}
	}

	return findings
}

// tlsAppLayerAuthRe matches application-layer authentication that can
// compensate for disabled transport verification: HMAC proofs, constant-time
// comparisons, explicit peer-certificate verification callbacks, and
// challenge/nonce machinery.
var tlsAppLayerAuthRe = regexp.MustCompile(`hmac\.|subtle\.ConstantTime|VerifyPeerCertificate|VerifyConnection|X-[A-Za-z0-9-]*(?:Proof|Signature|Nonce|Challenge)`)

// tlsCredentialHeaderRe matches code that places credentials into HTTP
// headers (matched against raw source: header names are string literals).
// Sending raw credentials over an unverified TLS channel is the dangerous
// case and stays high severity.
var tlsCredentialHeaderRe = regexp.MustCompile(`(?i)Header\.(?:Set|Add)\s*\([^)]{0,80}(?:password|authorization|cookie|token|api[-_]?key|secret|credential)`)

// tlsSeverityForBlock downgrades InsecureSkipVerify findings when the file
// implements compensating application-layer authentication, and keeps them
// high when the file transmits credential headers over the unverified
// channel.
func tlsSeverityForBlock(block diffSourceBlock) (severity, message string) {
	if tlsCredentialHeaderRe.MatchString(block.text) {
		return "high", "TLS certificate verification is disabled while credential headers are transmitted"
	}
	// Match against masked code so comments cannot supply downgrade evidence.
	// X-*-Proof header names live in string literals, so check those against
	// raw text only via the explicit header pattern.
	if tlsAppLayerAuthRe.MatchString(string(maskNonCode(block.file, block.text))) ||
		regexp.MustCompile(`Header\.(?:Set|Get|Add)\s*\(\s*"X-[A-Za-z0-9-]*(?:Proof|Signature|Nonce|Challenge)"`).MatchString(block.text) {
		return "medium", "TLS certificate verification is disabled; relies on application-layer authentication — verify all peers authenticate before trusting the channel"
	}
	return "high", "TLS certificate verification is disabled"
}

func insecureTLSLines(source string) []int {
	var scanner scanner.Scanner
	fset := token.NewFileSet()
	file := fset.AddFile("tls.go", fset.Base(), len(source))
	scanner.Init(file, []byte(source), nil, 0)
	var lines []int
	for {
		pos, tok, lit := scanner.Scan()
		if tok == token.EOF {
			return lines
		}
		if lit == "InsecureSkipVerify" {
			_, separator, _ := scanner.Scan()
			if separator != token.COLON && separator != token.ASSIGN {
				continue
			}
			_, valueToken, value := scanner.Scan()
			if valueToken == token.IDENT && value == "true" {
				lines = append(lines, file.Position(pos).Line)
			}
		}
	}
}
