package review

import (
	"fmt"
	"regexp"
	"strings"
)

// CleartextTransportRule flags Go HTTP servers that serve credential-bearing
// endpoints over plain HTTP: the process listens with ListenAndServe or an
// http.Server literal, the file shows no TLS configuration, and the same file
// handles tokens, passwords, or API keys. Remote deployments then expose
// credentials to network sniffing.
type CleartextTransportRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (CleartextTransportRule) Name() string { return "cleartext-transport" }

var (
	cleartextServerRe = regexp.MustCompile(`\bhttp\.ListenAndServe\s*\(|\bhttp\.Server\s*\{`)
	cleartextTLSRe    = regexp.MustCompile(`ListenAndServeTLS|ServeTLS|tls\.Config|TLSConfig|AutoTLS|certFile|keyFile|GetCertificate`)
	cleartextCredRe   = regexp.MustCompile(`(?i)token|password|secret|api_?key|authorization|credential|bearer`)
)

func (r CleartextTransportRule) Check(diff string) []Finding {
	var findings []Finding
	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		if !strings.HasSuffix(block.file, ".go") || strings.HasSuffix(block.file, "_test.go") {
			continue
		}
		code := string(maskNonCode(block.file, block.text))
		if !cleartextCredRe.MatchString(code) {
			continue
		}
		hasTLS := cleartextTLSRe.MatchString(code)
		for _, m := range cleartextServerRe.FindAllStringIndex(code, -1) {
			// http.ListenAndServe is always plaintext regardless of TLS
			// elsewhere in the file; only http.Server literals may be
			// configured for TLS (TLSConfig / ServeTLS).
			if hasTLS && strings.HasPrefix(code[m[0]:], "http.Server") {
				continue
			}
			// With TLS elsewhere in the file, the credential terms may belong
			// to the TLS listener's routes. Only flag this plaintext listener
			// when its own handler is tied to credential-bearing code.
			if hasTLS && !listenerHandlesCreds(block.text, code, m[1]) {
				continue
			}
			line := lineAtOffset(block.firstLine, code, m[0])
			if !block.addedLines[line] {
				continue
			}
			findings = append(findings, Finding{
				Category:    "security",
				Rule:        "cleartext-transport",
				Severity:    "medium",
				Confidence:  "medium",
				File:        block.file,
				Line:        line,
				Message:     "HTTP server without TLS serves credential-bearing endpoints; tokens and passwords traverse the network in cleartext",
				Remediation: "Terminate TLS (ListenAndServeTLS, a TLS-terminating reverse proxy, or mTLS) before exposing credential-bearing endpoints; never send API tokens over plain HTTP to remote clients.",
			})
		}
	}
	return findings
}

// listenerHandlesCreds reports whether the handler passed to the
// ListenAndServe call whose '(' ends at callEnd is referenced on any line that
// also mentions credentials. A nil/default handler or an unparseable argument
// is treated conservatively as credential-bearing.
func listenerHandlesCreds(raw, code string, callEnd int) bool {
	args := splitTopLevelArgs(sinkArgSpan(code, callEnd-1))
	if len(args) < 2 {
		return true
	}
	handler := strings.TrimSpace(args[1])
	if handler == "" || handler == "nil" || !regexp.MustCompile(`^\w+$`).MatchString(handler) {
		return true
	}
	identRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(handler) + `\b`)
	for _, ln := range strings.Split(raw, "\n") {
		if identRe.MatchString(ln) && cleartextCredRe.MatchString(ln) {
			return true
		}
	}
	return false
}

// UnauthenticatedRouteRule flags parameterized/wildcard HTTP routes registered
// outside the authenticated API namespace in files that do apply auth
// middleware elsewhere — a common sign that a handler was mounted outside the
// protected route group.
type UnauthenticatedRouteRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (UnauthenticatedRouteRule) Name() string { return "unauthenticated-route" }

var (
	chiRouteRe     = regexp.MustCompile(`\b\w+\.(?:Get|Post|Put|Delete|Patch|Head|Options|Handle|Method|Route|Mount|HandleFunc|GetFunc|PostFunc)\s*\(\s*"(/[^"]*)"`)
	chiAPIRouteRe  = regexp.MustCompile(`\.Route\s*\(\s*"(/api[^"]*)"`)
	authMiddleware = regexp.MustCompile(`requireScope|Authenticate|AuthMiddleware|Authorization|Bearer|apiKey|APIKey|authToken|checkAuth`)
	// chiWithRe finds `x := r.With(middleware)` receivers; when the middleware
	// argument looks auth-related, routes registered on x are authenticated.
	chiWithRe       = regexp.MustCompile(`(\w+)\s*:?=\s*\w+\.With\s*\(([^)]{0,300})\)`)
	authMiddleware2 = regexp.MustCompile(`(?i)(?:requireScope|authenticat|\bauthorization\b|bearer|apikey|\w*auth\w*)`)
)

// braceSpanEnd returns the offset just past the '}' matching the '{' at open,
// or -1 when unbalanced. Bounded scan.
func braceSpanEnd(code string, open int) int {
	depth := 0
	for i := open; i < len(code) && i < open+60000; i++ {
		switch code[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

// apiGroupSpans returns byte ranges of r.Route("/api...") group bodies so
// nested routes are recognized as inside the authenticated namespace.
func apiGroupSpans(code string) [][2]int {
	var spans [][2]int
	for _, m := range chiAPIRouteRe.FindAllStringIndex(code, -1) {
		// Find the func literal body after the Route("/api..", func(...) { ... })
		rest := code[m[1]:]
		fi := strings.Index(rest, "func")
		if fi < 0 {
			continue
		}
		bi := strings.Index(rest[fi:], "{")
		if bi < 0 {
			continue
		}
		open := m[1] + fi + bi
		if end := braceSpanEnd(code, open); end > 0 {
			spans = append(spans, [2]int{m[0], end})
		}
	}
	return spans
}

func insideAnySpan(offset int, spans [][2]int) bool {
	for _, s := range spans {
		if offset >= s[0] && offset < s[1] {
			return true
		}
	}
	return false
}

// routeReceiver returns the identifier preceding the method call at the start
// of a chiRouteRe match (e.g. "pluginUI" from `pluginUI.Get("/x", h)`).
func routeReceiver(match string) string {
	end := strings.IndexByte(match, '.')
	if end <= 0 {
		return ""
	}
	return match[:end]
}

func (r UnauthenticatedRouteRule) Check(diff string) []Finding {
	var findings []Finding
	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		if !strings.HasSuffix(block.file, ".go") || strings.HasSuffix(block.file, "_test.go") {
			continue
		}
		code := string(maskNonCode(block.file, block.text))
		if !authMiddleware.MatchString(code) {
			continue
		}
		groups := apiGroupSpans(block.text)
		// Receivers bound via r.With(<auth middleware>) register authenticated
		// routes even outside the /api group.
		authedRecv := make(map[string]bool)
		for _, wm := range chiWithRe.FindAllStringSubmatch(block.text, -1) {
			if authMiddleware2.MatchString(wm[2]) {
				authedRecv[wm[1]] = true
			}
		}
		seen := make(map[int]bool)
		// Route paths are string literals (blanked by masking), so match on raw
		// text and skip comment occurrences.
		for _, m := range chiRouteRe.FindAllStringSubmatchIndex(block.text, -1) {
			if offsetInComment(block.file, block.text, m[0]) {
				continue
			}
			if insideAnySpan(m[0], groups) {
				continue
			}
			// Skip routes registered on a receiver wrapped with auth
			// middleware (e.g. pluginUI := r.With(srv.pluginUIAuth)).
			if recv := routeReceiver(block.text[m[0]:]); authedRecv[recv] {
				continue
			}
			path := block.text[m[2]:m[3]]
			// Only parameterized routes outside the /api namespace are
			// suspicious; static mounts and the API group itself are expected.
			if strings.HasPrefix(path, "/api/") || !strings.Contains(path, "{") {
				continue
			}
			line := lineAtOffset(block.firstLine, code, m[0])
			if seen[line] || !block.addedLines[line] {
				continue
			}
			seen[line] = true
			findings = append(findings, Finding{
				Category:    "security",
				Rule:        "unauthenticated-route",
				Severity:    "low",
				Confidence:  "low",
				File:        block.file,
				Line:        line,
				Message:     fmt.Sprintf("Parameterized route %s registered outside the authenticated /api namespace in a file that uses auth middleware", path),
				Remediation: "Verify this route is intentionally public; otherwise mount it inside the authenticated route group or add explicit authorization checks.",
			})
		}
	}
	return findings
}
