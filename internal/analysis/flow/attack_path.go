package flow

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// PathStatus classifies the outcome and confidence of an attack-path query.
type PathStatus string

const (
	// PathConfirmed: An unsanitized, concrete path reaches a sensitive sink.
	PathConfirmed PathStatus = "confirmed"
	// PathPotential: A path reaches a sink but contains dynamic dispatch or unresolved calls.
	PathPotential PathStatus = "potential"
	// PathBlocked: The path passes through a recognized sanitizer or validation guard.
	PathBlocked PathStatus = "blocked"
	// PathIncomplete: The path search was truncated due to budget limits or cyclic recursion.
	PathIncomplete PathStatus = "incomplete"
)

// AttackPathNode describes one node along a traced attack path.
type AttackPathNode struct {
	Kind     string            `json:"kind"` // "source", "transform", "call", "sanitizer", "sink"
	ValueID  string            `json:"value_id,omitempty"`
	Function string            `json:"function,omitempty"`
	File     string            `json:"file,omitempty"`
	Line     int               `json:"line,omitempty"`
	Detail   string            `json:"detail"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// AttackPath is an end-to-end traced attack path from untrusted source to sink.
type AttackPath struct {
	ID          string           `json:"id"`
	RuleID      string           `json:"rule_id"`
	Category    string           `json:"category"`
	Status      PathStatus       `json:"status"`
	Source      AttackPathNode   `json:"source"`
	Sink        AttackPathNode   `json:"sink"`
	Sanitizers  []AttackPathNode `json:"sanitizers,omitempty"`
	Steps       []AttackPathNode `json:"steps"`
	Truncated   bool             `json:"truncated,omitempty"`
	TruncReason string           `json:"trunc_reason,omitempty"`
}

// AttackPathOptions configures attack-path discovery.
type AttackPathOptions struct {
	MaxPaths       int
	MaxDepth       int
	IncludeBlocked bool
}

type sinkDef struct {
	category    string
	ruleID      string
	severity    string
	remediation string
	pattern     *regexp.Regexp
}

var (
	sourceCallRe = regexp.MustCompile(
		`(?i)(?:URLParam|URL\.Query|FormValue|PostFormValue|` +
			`PathValue|MultipartForm|ReadBody|Decode|Unmarshal)`,
	)
	sanitizerCallRe = regexp.MustCompile(
		`(?i)(?:filepath\.Base|filepath\.Clean|filepath\.Rel|` +
			`html\.EscapeString|strconv\.Atoi|strconv\.Parse|` +
			`url\.QueryEscape|url\.PathEscape|sanitize|validate|` +
			`verify|clean|escape|allowlist|whitelist)`,
	)
)

var sinkCatalog = []sinkDef{
	{
		category: "command-injection",
		ruleID:   "flow-command-injection",
		severity: "critical",
		remediation: "Pass arguments as separate command arguments; " +
			"never execute user-controlled commands.",
		pattern: regexp.MustCompile(`(?i)(?:exec\.Command|exec\.CommandContext|plugin\.Open)`),
	},
	{
		category: "sql-injection",
		ruleID:   "flow-sql-injection",
		severity: "critical",
		remediation: "Use parameterized queries or prepared statements; " +
			"never interpolate input into queries.",
		pattern: regexp.MustCompile(`(?i)(?:\bDB\b\.(?:Query|QueryRow|Exec)|sql\.(?:Open|Query))`),
	},
	{
		category: "path-traversal",
		ruleID:   "flow-path-traversal",
		severity: "high",
		remediation: "Validate paths with filepath.Clean and filepath.Rel " +
			"to prevent directory traversal.",
		pattern: regexp.MustCompile(
			`(?i)(?:os\.(?:Open|Create|Remove|RemoveAll|WriteFile|ReadFile|Rename)|` +
				`ioutil\.(?:ReadFile|WriteFile))`,
		),
	},
	{
		category: "ssrf",
		ruleID:   "flow-ssrf",
		severity: "high",
		remediation: "Validate destination hostnames against an allowlist " +
			"before making outbound HTTP requests.",
		pattern: regexp.MustCompile(
			`(?i)(?:http\.(?:Get|Post|Head|NewRequest|NewRequestWithContext)|client\.(?:Do|Get|Post))`,
		),
	},
}

type sourceCandidate struct {
	val  *semantic.Value
	node AttackPathNode
}

type sinkCandidate struct {
	fn    *semantic.Function
	instr *semantic.Instruction
	call  *semantic.Call
	def   sinkDef
}

func collectFunctionSources(fn *semantic.Function) []sourceCandidate {
	var sources []sourceCandidate
	lowerName := strings.ToLower(fn.Name)
	isEntry := fn.Exported || strings.Contains(lowerName, "handler") ||
		strings.Contains(lowerName, "serve")

	for _, val := range fn.Values {
		if val.Kind == semantic.ValueParam && isEntry {
			sources = append(sources, sourceCandidate{
				val: val,
				node: AttackPathNode{
					Kind:     "source",
					ValueID:  val.ID,
					Function: fn.ID,
					File:     val.Position.File,
					Line:     val.Position.Line,
					Detail:   fmt.Sprintf("entrypoint parameter %s in %s", val.Name, fn.Name),
				},
			})
		}
	}

	for _, call := range fn.Calls {
		if call == nil || call.Site == nil || !sourceCallRe.MatchString(call.Target) {
			continue
		}
		for _, outVal := range call.Site.Outputs {
			sources = append(sources, sourceCandidate{
				val: outVal,
				node: AttackPathNode{
					Kind:     "source",
					ValueID:  outVal.ID,
					Function: fn.ID,
					File:     call.Site.Position.File,
					Line:     call.Site.Position.Line,
					Detail:   fmt.Sprintf("source call %s in %s", call.Target, fn.Name),
				},
			})
		}
	}
	return sources
}

func collectFunctionSinks(fn *semantic.Function) []sinkCandidate {
	var sinks []sinkCandidate
	for _, call := range fn.Calls {
		if call == nil || call.Site == nil {
			continue
		}
		for _, def := range sinkCatalog {
			if def.pattern.MatchString(call.Target) {
				sinks = append(sinks, sinkCandidate{
					fn:    fn,
					instr: call.Site,
					call:  call,
					def:   def,
				})
			}
		}
	}
	return sinks
}

func collectSourcesAndSinks(prog *semantic.Program) ([]sourceCandidate, []sinkCandidate) {
	var sources []sourceCandidate
	var sinks []sinkCandidate
	for _, pkg := range prog.Packages {
		for _, fn := range pkg.Functions {
			sources = append(sources, collectFunctionSources(fn)...)
			sinks = append(sinks, collectFunctionSinks(fn)...)
		}
	}
	return sources, sinks
}

func evaluatePathTrace(
	srcNode AttackPathNode,
	sinkCand sinkCandidate,
	events []FlowEvent,
	truncated bool,
	maxDepth int,
) AttackPath {
	sinkPos := sinkCand.instr.Position
	sinkNode := AttackPathNode{
		Kind:     "sink",
		Function: sinkCand.fn.ID,
		File:     sinkPos.File,
		Line:     sinkPos.Line,
		Detail:   fmt.Sprintf("sensitive sink %s", sinkCand.call.Target),
	}

	steps := make([]AttackPathNode, 0, len(events)+2)
	steps = append(steps, srcNode)

	var sanitizers []AttackPathNode
	hasDynamic := false

	for _, ev := range events {
		kind := "transform"
		if ev.Via == "call-arg" || ev.Via == "call-result" {
			kind = "call"
		}
		isSanitizer := sanitizerCallRe.MatchString(ev.Detail)
		if isSanitizer {
			kind = "sanitizer"
		}
		if strings.Contains(strings.ToLower(ev.Detail), "dynamic") {
			hasDynamic = true
		}

		node := AttackPathNode{
			Kind:     kind,
			ValueID:  ev.ValueID,
			Function: ev.FunctionID,
			File:     ev.Position.File,
			Line:     ev.Position.Line,
			Detail:   ev.Detail,
		}
		if isSanitizer {
			sanitizers = append(sanitizers, node)
		}
		steps = append(steps, node)
	}
	steps = append(steps, sinkNode)

	status := PathConfirmed
	var truncReason string
	switch {
	case len(sanitizers) > 0:
		status = PathBlocked
	case truncated || len(steps) > maxDepth:
		status = PathIncomplete
		truncReason = "path depth or event threshold exceeded"
	case hasDynamic || sinkCand.call.Dynamic:
		status = PathPotential
	}

	pathID := fmt.Sprintf("%s->%s:%d", srcNode.Detail, sinkCand.def.category, sinkPos.Line)
	return AttackPath{
		ID:          pathID,
		RuleID:      sinkCand.def.ruleID,
		Category:    sinkCand.def.category,
		Status:      status,
		Source:      srcNode,
		Sink:        sinkNode,
		Sanitizers:  sanitizers,
		Steps:       steps,
		Truncated:   truncated,
		TruncReason: truncReason,
	}
}

func pathEvidenceSteps(p AttackPath) []analysis.EvidenceStep {
	evSteps := make([]analysis.EvidenceStep, 0, len(p.Steps))
	for i, step := range p.Steps {
		var kind analysis.EvidenceKind
		switch step.Kind {
		case "source":
			kind = analysis.EvidenceSource
		case "sink":
			kind = analysis.EvidenceSink
		case "call":
			kind = analysis.EvidenceCall
		case "sanitizer":
			kind = analysis.EvidenceState
		default:
			kind = analysis.EvidenceNote
		}

		span := analysis.Span{}
		if step.File != "" {
			span = analysis.SingleLineSpan(step.File, step.Line)
		}
		note := step.Detail
		if note == "" {
			note = fmt.Sprintf("step %d (%s)", i+1, step.Kind)
		}

		evSteps = append(evSteps, analysis.EvidenceStep{
			Kind: kind,
			Span: span,
			Note: note,
		})
	}
	return evSteps
}

func convertPathToFinding(p AttackPath, def sinkDef) (analysis.Finding, error) {
	sinkSpan := analysis.SingleLineSpan(p.Sink.File, p.Sink.Line)
	spans := []analysis.Span{sinkSpan}
	if p.Source.File != "" {
		spans = append(spans, analysis.SingleLineSpan(p.Source.File, p.Source.Line))
	}

	conf := analysis.ConfidenceHigh
	status := analysis.StatusProven
	if p.Status != PathConfirmed {
		conf = analysis.ConfidenceMedium
		status = analysis.StatusPotential
	}

	msg := fmt.Sprintf(
		"Untrusted data from %s flows into %s without verified validation.",
		p.Source.Detail, p.Sink.Detail,
	)

	f := analysis.Finding{
		RuleID:      def.ruleID,
		RuleName:    def.ruleID,
		Analyzer:    "flow",
		Message:     msg,
		Category:    "security",
		Severity:    def.severity,
		Confidence:  conf,
		Status:      status,
		Trace:       analysis.TraceSourceToSink,
		Spans:       spans,
		Evidence:    pathEvidenceSteps(p),
		Remediation: def.remediation,
	}

	f = f.EnsureID()
	if err := f.Validate(); err != nil {
		return f, err
	}
	return f, nil
}

func matchSinkOperand(
	src sourceCandidate,
	sink sinkCandidate,
	flowRes *FlowResult,
	opts AttackPathOptions,
) (*AttackPath, *analysis.Finding) {
	for _, op := range sink.instr.Operands {
		if op == nil {
			continue
		}
		if _, reached := flowRes.parents[op.ID]; !reached {
			continue
		}
		events := flowRes.Trace(op.ID)
		p := evaluatePathTrace(src.node, sink, events, flowRes.Truncated, opts.MaxDepth)
		if p.Status == PathBlocked && !opts.IncludeBlocked {
			return nil, nil
		}
		f, _ := convertPathToFinding(p, sink.def)
		if p.Status == PathConfirmed || p.Status == PathPotential {
			return &p, &f
		}
		return &p, nil
	}
	return nil, nil
}

func matchSinkPaths(
	src sourceCandidate,
	sinks []sinkCandidate,
	flowRes *FlowResult,
	opts AttackPathOptions,
) ([]AttackPath, []analysis.Finding) {
	var paths []AttackPath
	var findings []analysis.Finding

	for _, sink := range sinks {
		p, f := matchSinkOperand(src, sink, flowRes, opts)
		if p != nil {
			paths = append(paths, *p)
		}
		if f != nil {
			findings = append(findings, *f)
		}
	}
	return paths, findings
}

// FindAttackPaths analyzes prog for interprocedural attack paths connecting sources to sinks.
func FindAttackPaths(
	ctx context.Context,
	a *Analyzer,
	opts AttackPathOptions,
) ([]AttackPath, []analysis.Finding, error) {
	if a == nil || a.prog == nil {
		return nil, nil, nil
	}
	if opts.MaxPaths <= 0 {
		opts.MaxPaths = 32
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 30
	}

	sources, sinks := collectSourcesAndSinks(a.prog)
	if len(sources) == 0 || len(sinks) == 0 {
		return nil, nil, nil
	}

	var paths []AttackPath
	var findings []analysis.Finding

	for _, src := range sources {
		select {
		case <-ctx.Done():
			return paths, findings, ctx.Err()
		default:
		}
		if len(paths) >= opts.MaxPaths {
			break
		}

		flowRes := a.Flow(src.val)
		if flowRes == nil {
			continue
		}

		newPaths, newFindings := matchSinkPaths(src, sinks, flowRes, opts)
		paths = append(paths, newPaths...)
		findings = append(findings, newFindings...)
	}

	sort.Slice(paths, func(i, j int) bool {
		return paths[i].ID < paths[j].ID
	})
	return paths, findings, nil
}
