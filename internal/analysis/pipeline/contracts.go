package pipeline

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
	"github.com/jakej985-rgb/m3tal-review/internal/analysis/authproto"
	"github.com/jakej985-rgb/m3tal-review/internal/analysis/protocol"
	"github.com/jakej985-rgb/m3tal-review/internal/analysis/statemachine"
	"github.com/jakej985-rgb/m3tal-review/internal/analysis/typestate"
	"gopkg.in/yaml.v3"
)

// Contract discovery bounds: contract documents are user-supplied
// configuration, so they are size- and count-capped like every other
// repo-read input in the tool.
const (
	maxContractFiles      = 512
	maxContractBytes      = 1 << 20 // 1 MiB per file
	maxContractsPerFamily = 256
)

// Contracts holds the parsed contract/spec sets discovered under
// Options.ContractDir, grouped by analyzer family.
type Contracts struct {
	// StateMachine holds statemachine/1 documents.
	StateMachine []*statemachine.Contract
	// TypeState holds typestate/1 documents.
	TypeState []*typestate.Spec
	// AuthProto holds authproto/1 documents.
	AuthProto []*authproto.Contract
	// Protocol is the snapshot set built from protocol/1 documents.
	Protocol *protocol.SnapshotSet
	// ProtocolVersions lists the deployed-version labels present in
	// the snapshot set, sorted. It is the version list handed to
	// protocol.EvaluateMatrix.
	ProtocolVersions []string
}

// discoverContracts scans dir for *.yaml/*.yml documents and routes
// each to its parser by the mandatory schema_version field. Missing
// directories are not an error. Parse and validation problems are
// returned as diagnostics; valid documents of unrecognized schema
// versions are reported and skipped.
func discoverContracts(dir string) (*Contracts, []analysis.Diagnostic) {
	out := &Contracts{}
	var diags []analysis.Diagnostic

	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, []analysis.Diagnostic{{
			Severity: analysis.DiagSeverityWarning,
			Category: analysis.DiagLoadError,
			Message:  fmt.Sprintf("cannot stat contract directory %s: %v", dir, err),
		}}
	}
	if !info.IsDir() {
		return out, []analysis.Diagnostic{{
			Severity: analysis.DiagSeverityWarning,
			Category: analysis.DiagLoadError,
			Message:  fmt.Sprintf("contract path %s is not a directory", dir),
		}}
	}

	var files []string
	count := 0
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries; WalkDir continues
		}
		if d.IsDir() {
			// Never descend into VCS or build output.
			if d.Name() == ".git" || d.Name() == "vendor" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		count++
		if count > maxContractFiles {
			diags = append(diags, analysis.Diagnostic{
				Severity: analysis.DiagSeverityWarning,
				Category: analysis.DiagLimit,
				Message:  fmt.Sprintf("contract file count exceeds %d; remaining files ignored", maxContractFiles),
			})
			return filepath.SkipAll
		}
		files = append(files, path)
		return nil
	})
	sort.Strings(files)

	for _, path := range files {
		rel, _ := filepath.Rel(dir, path)
		data, err := os.ReadFile(path)
		if err != nil {
			diags = append(diags, analysis.Diagnostic{
				Severity: analysis.DiagSeverityWarning,
				Category: analysis.DiagLoadError,
				Message:  fmt.Sprintf("cannot read contract %s: %v", rel, err),
			})
			continue
		}
		if len(data) > maxContractBytes {
			diags = append(diags, analysis.Diagnostic{
				Severity: analysis.DiagSeverityWarning,
				Category: analysis.DiagLimit,
				Message:  fmt.Sprintf("contract %s exceeds %d bytes; ignored", rel, maxContractBytes),
			})
			continue
		}
		dispatchContract(out, path, rel, data, &diags)
	}

	finalizeProtocol(out, &diags)
	return out, diags
}

// schemaProbe extracts only the schema_version field for routing.
type schemaProbe struct {
	SchemaVersion string `yaml:"schema_version"`
}

func dispatchContract(c *Contracts, path, rel string, data []byte, diags *[]analysis.Diagnostic) {
	var probe schemaProbe
	if err := yaml.Unmarshal(data, &probe); err != nil {
		*diags = append(*diags, analysis.Diagnostic{
			Severity: analysis.DiagSeverityError,
			Category: analysis.DiagParseError,
			Message:  fmt.Sprintf("contract %s: invalid YAML: %v", rel, err),
			Span:     analysis.Span{File: path},
		})
		return
	}
	switch probe.SchemaVersion {
	case statemachine.SchemaVersion:
		contract, err := statemachine.ParseContract(data)
		if err != nil {
			*diags = append(*diags, parseDiag(rel, path, err))
			return
		}
		if len(c.StateMachine) >= maxContractsPerFamily {
			limitDiag(diags, "statemachine/1")
			return
		}
		c.StateMachine = append(c.StateMachine, contract)
		*diags = append(*diags, contract.Check()...)
	case typestate.SchemaVersion:
		spec, err := typestate.ParseSpec(data)
		if err != nil {
			*diags = append(*diags, parseDiag(rel, path, err))
			return
		}
		if len(c.TypeState) >= maxContractsPerFamily {
			limitDiag(diags, "typestate/1")
			return
		}
		c.TypeState = append(c.TypeState, spec)
		*diags = append(*diags, spec.Check()...)
	case authproto.SchemaVersion:
		contract, err := authproto.ParseContract(data)
		if err != nil {
			*diags = append(*diags, parseDiag(rel, path, err))
			return
		}
		if len(c.AuthProto) >= maxContractsPerFamily {
			limitDiag(diags, "authproto/1")
			return
		}
		c.AuthProto = append(c.AuthProto, contract)
		*diags = append(*diags, contract.Check()...)
	case protocol.SchemaVersion:
		// protocol snapshots are collected and assembled into a
		// SnapshotSet by finalizeProtocol.
		snap, err := protocol.LoadSnapshot(path)
		if err != nil {
			*diags = append(*diags, analysis.Diagnostic{
				Severity: analysis.DiagSeverityError,
				Category: analysis.DiagParseError,
				Message:  fmt.Sprintf("protocol snapshot %s: %v", rel, err),
				Span:     analysis.Span{File: path},
			})
			return
		}
		if c.Protocol == nil {
			c.Protocol = &protocol.SnapshotSet{ByVersion: make(map[string]*protocol.Snapshot)}
		}
		if c.Protocol.Protocol == "" {
			c.Protocol.Protocol = snap.Contract.ID
		}
		for _, d := range snap.Contract.Check() {
			*diags = append(*diags, d)
		}
		if prev, dup := c.Protocol.ByVersion[snap.Version]; dup {
			*diags = append(*diags, analysis.Diagnostic{
				Severity: analysis.DiagSeverityError,
				Category: analysis.DiagParseError,
				Message: fmt.Sprintf("duplicate protocol snapshot version %q (%s and %s)",
					snap.Version, prev.Source, snap.Source),
			})
			return
		}
		c.Protocol.ByVersion[snap.Version] = snap
	default:
		*diags = append(*diags, analysis.Diagnostic{
			Severity: analysis.DiagSeverityWarning,
			Category: analysis.DiagUnsupported,
			Message: fmt.Sprintf("contract %s: unrecognized schema_version %q; supported: statemachine/1, typestate/1, authproto/1, protocol/1",
				rel, probe.SchemaVersion),
			Span: analysis.Span{File: path},
		})
	}
}

// finalizeProtocol assembles ProtocolVersions and load diagnostics
// once all snapshots are known.
func finalizeProtocol(c *Contracts, diags *[]analysis.Diagnostic) {
	if c.Protocol == nil {
		return
	}
	versions := make([]string, 0, len(c.Protocol.ByVersion))
	for v := range c.Protocol.ByVersion {
		versions = append(versions, v)
	}
	sort.Strings(versions)
	c.ProtocolVersions = versions
	*diags = append(*diags, c.Protocol.Diagnostics...)
}

func parseDiag(rel, path string, err error) analysis.Diagnostic {
	return analysis.Diagnostic{
		Severity: analysis.DiagSeverityError,
		Category: analysis.DiagParseError,
		Message:  fmt.Sprintf("contract %s: %v", rel, err),
		Span:     analysis.Span{File: path},
	}
}

func limitDiag(diags *[]analysis.Diagnostic, family string) {
	*diags = append(*diags, analysis.Diagnostic{
		Severity: analysis.DiagSeverityWarning,
		Category: analysis.DiagLimit,
		Message:  fmt.Sprintf("%s contract count exceeds %d; remaining documents ignored", family, maxContractsPerFamily),
	})
}
