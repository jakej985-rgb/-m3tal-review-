package review

import (
	"sort"
	"strings"
)

// InferAnalyzer determines the producing analyzer for a finding based on rule prefix
// or existing analyzer metadata.
func InferAnalyzer(f Finding) string {
	if len(f.Analyzers) > 0 && f.Analyzers[0] != "" {
		return f.Analyzers[0]
	}
	rule := strings.TrimSpace(f.Rule)
	switch {
	case strings.HasPrefix(rule, "gitleaks-"):
		return "gitleaks"
	case strings.HasPrefix(rule, "gosec-"):
		return "gosec"
	case strings.HasPrefix(rule, "osv-"):
		return "osv-scanner"
	case rule == "dependency-cve":
		return "osv-api"
	case strings.HasPrefix(rule, "tool-"):
		return "tool-runner"
	default:
		return "m3tal-review"
	}
}

// GroupFindings groups duplicate findings from multiple analyzers on the same target,
// preserving underlying analyzer evidence, raw severities, advisory IDs, and individual rule identifiers.
func GroupFindings(findings []Finding) []Finding {
	if len(findings) <= 1 {
		if len(findings) == 1 {
			analyzer := InferAnalyzer(findings[0])
			normPath := NormalizeFindingPath(findings[0].File)
			grp := newFindingGroup(findings[0], normPath, analyzer)
			return AssignFindingIDs([]Finding{grp.toFinding()})
		}
		return findings
	}

	groups := make([]*findingGroup, 0)

	for _, f := range findings {
		placed := false
		analyzer := InferAnalyzer(f)
		normPath := NormalizeFindingPath(f.File)

		for _, grp := range groups {
			if grp.matches(f, normPath, analyzer) {
				grp.add(f, analyzer)
				placed = true
				break
			}
		}

		if !placed {
			grp := newFindingGroup(f, normPath, analyzer)
			groups = append(groups, grp)
		}
	}

	result := make([]Finding, 0, len(groups))
	for _, grp := range groups {
		result = append(result, grp.toFinding())
	}

	return AssignFindingIDs(result)
}

func ruleSemanticDomain(rule, analyzer string) string {
	r := strings.ToLower(strings.TrimSpace(rule))
	r = strings.TrimPrefix(r, "gosec-")
	r = strings.TrimPrefix(r, "gitleaks-")
	r = strings.TrimPrefix(r, "osv-")

	switch {
	case analyzer == "gitleaks" || strings.HasPrefix(rule, "gitleaks-") ||
		r == "hardcoded-credential" || r == "hardcoded-secret" || r == "secret-file" ||
		r == "g101" || strings.Contains(r, "secret") || strings.Contains(r, "credential") || strings.Contains(r, "password") || strings.Contains(r, "api-key"):
		return "secret"

	case r == "risky-shell-execution" || r == "g204" || strings.Contains(r, "command-injection") || strings.Contains(r, "shell"):
		return "command-injection"

	case r == "world-writable-file-mode" || r == "g301" || r == "g302" || strings.Contains(r, "file-mode") || strings.Contains(r, "file-perms"):
		return "file-permissions"

	case r == "insecure-tls-verification" || r == "g402" || strings.Contains(r, "tls") || strings.Contains(r, "ssl"):
		return "tls"

	case r == "ssh-insecure-host-key" || r == "g106" || strings.Contains(r, "host-key"):
		return "ssh-host-key"

	case r == "sql-injection" || r == "g201" || r == "g202" || strings.Contains(r, "sql"):
		return "sql-injection"

	case r == "weak-crypto" || r == "insecure-crypto" || strings.HasPrefix(r, "g40") || strings.HasPrefix(r, "g50"):
		return "crypto"

	case rule == "dependency-cve" || strings.HasPrefix(rule, "osv-") || analyzer == "osv-scanner" || analyzer == "osv-api":
		return "dependency-cve"

	default:
		return ""
	}
}

type findingGroup struct {
	normPath     string
	primary      Finding
	findings     []Finding
	analyzersSet map[string]bool
	rulesSet     map[string]bool
	advisories   map[string]bool
	evidences    []FindingEvidence
}

func newFindingGroup(f Finding, normPath, analyzer string) *findingGroup {
	grp := &findingGroup{
		normPath:     normPath,
		primary:      f,
		findings:     []Finding{f},
		analyzersSet: make(map[string]bool),
		rulesSet:     make(map[string]bool),
		advisories:   make(map[string]bool),
	}
	grp.analyzersSet[analyzer] = true
	if len(f.Analyzers) > 0 {
		for _, a := range f.Analyzers {
			if a != "" {
				grp.analyzersSet[a] = true
			}
		}
	}
	if f.Rule != "" {
		grp.rulesSet[f.Rule] = true
	}
	for _, r := range f.Rules {
		if r != "" {
			grp.rulesSet[r] = true
		}
	}
	if f.AdvisoryID != "" {
		grp.advisories[f.AdvisoryID] = true
	}
	for _, adv := range f.AdvisoryIDs {
		if adv != "" {
			grp.advisories[adv] = true
		}
	}

	if len(f.Evidence) > 0 {
		grp.evidences = append(grp.evidences, f.Evidence...)
	} else {
		grp.evidences = append(grp.evidences, FindingEvidence{
			Analyzer:    analyzer,
			Rule:        f.Rule,
			Severity:    f.Severity,
			RawSeverity: f.RawSeverity,
			Confidence:  f.Confidence,
			Message:     f.Message,
			Line:        f.Line,
		})
	}

	return grp
}

func (g *findingGroup) matches(f Finding, normPath, analyzer string) bool {
	if g.normPath != normPath {
		return false
	}

	// 1. Check shared advisory IDs (e.g. CVE, GHSA, CWE)
	if f.AdvisoryID != "" && g.advisories[f.AdvisoryID] {
		return true
	}
	for _, adv := range f.AdvisoryIDs {
		if adv != "" && g.advisories[adv] {
			return true
		}
	}

	// 2. Check identical base key (identical substantive signature on same file)
	if BaseFindingKey(f) == BaseFindingKey(g.primary) {
		return true
	}

	// Findings from the same analyzer with different rules are distinct issues.
	if g.analyzersSet[analyzer] {
		return false
	}

	// 3. Same line across different analyzers with matching domain or signature
	if f.Line > 0 && f.Line == g.primary.Line {
		dom1 := ruleSemanticDomain(g.primary.Rule, InferAnalyzer(g.primary))
		dom2 := ruleSemanticDomain(f.Rule, analyzer)
		if dom1 != "" && dom1 == dom2 {
			return true
		}
		if SubstantiveFindingSignature(f) == SubstantiveFindingSignature(g.primary) {
			return true
		}
		cleanRule1 := strings.TrimPrefix(strings.TrimPrefix(g.primary.Rule, "gosec-"), "gitleaks-")
		cleanRule2 := strings.TrimPrefix(strings.TrimPrefix(f.Rule, "gosec-"), "gitleaks-")
		if cleanRule1 == cleanRule2 {
			return true
		}
	}

	return false
}

func (g *findingGroup) add(f Finding, analyzer string) {
	g.findings = append(g.findings, f)
	g.analyzersSet[analyzer] = true
	if len(f.Analyzers) > 0 {
		for _, a := range f.Analyzers {
			if a != "" {
				g.analyzersSet[a] = true
			}
		}
	}
	if f.Rule != "" {
		g.rulesSet[f.Rule] = true
	}
	for _, r := range f.Rules {
		if r != "" {
			g.rulesSet[r] = true
		}
	}
	if f.AdvisoryID != "" {
		g.advisories[f.AdvisoryID] = true
	}
	for _, adv := range f.AdvisoryIDs {
		if adv != "" {
			g.advisories[adv] = true
		}
	}

	if len(f.Evidence) > 0 {
		g.evidences = append(g.evidences, f.Evidence...)
	} else {
		ev := FindingEvidence{
			Analyzer:    analyzer,
			Rule:        f.Rule,
			Severity:    f.Severity,
			RawSeverity: f.RawSeverity,
			Confidence:  f.Confidence,
			Message:     f.Message,
			Line:        f.Line,
		}
		g.evidences = append(g.evidences, ev)
	}

	// Promote primary if f has higher severity
	if SeverityRank(f.Severity) > SeverityRank(g.primary.Severity) {
		g.primary = f
	}
}

func (g *findingGroup) toFinding() Finding {
	out := g.primary
	out.ID = ""

	// Compute sorted rules
	rules := make([]string, 0, len(g.rulesSet))
	for r := range g.rulesSet {
		rules = append(rules, r)
	}
	sort.Strings(rules)
	out.Rules = rules

	// Compute sorted analyzers
	analyzers := make([]string, 0, len(g.analyzersSet))
	for a := range g.analyzersSet {
		analyzers = append(analyzers, a)
	}
	sort.Strings(analyzers)
	out.Analyzers = analyzers

	// Compute max severity and max confidence
	maxSev := out.Severity
	maxConf := out.Confidence
	for _, f := range g.findings {
		maxSev = MaxSeverity(maxSev, f.Severity)
		maxConf = MaxConfidence(maxConf, f.Confidence)
	}
	// If multiple distinct analyzers agree, confidence is high
	if len(analyzers) > 1 {
		maxConf = "high"
	}
	out.Severity = maxSev
	out.Confidence = maxConf

	// Compute sorted advisory IDs
	advisories := make([]string, 0, len(g.advisories))
	for adv := range g.advisories {
		advisories = append(advisories, adv)
	}
	sort.Strings(advisories)
	out.AdvisoryIDs = advisories
	if out.AdvisoryID == "" && len(advisories) > 0 {
		out.AdvisoryID = advisories[0]
	}

	out.Evidence = g.evidences
	return out
}
