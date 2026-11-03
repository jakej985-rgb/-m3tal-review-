package review

import (
	"go/scanner"
	"go/token"
	"path"
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
		blocks := diffSourceBlocksForFile(diff, fileDiff.Path)
		if source, err := readRuleSource(r.RepositoryRoot, fileDiff.Path, r.WorkingTree); err == nil {
			blocks = []diffSourceBlock{fullSourceBlock(fileDiff.Path, source, fileDiff.AddedLines)}
		}
		for _, block := range blocks {
			for _, line := range insecureTLSLines(block.text) {
				if !block.addedLines[line] {
					continue
				}
				findings = append(findings, Finding{Rule: "insecure-tls-verification", Severity: "high", File: block.file, Line: line, Message: "TLS certificate verification is disabled", Remediation: "Remove InsecureSkipVerify or set it to false to ensure secure connections."})
			}
		}
	}

	return findings
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
