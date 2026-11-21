package review

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

// DesignSystemRule dynamically ingests markdown design system guides in the
// repository (e.g. design_system/*.md) and checks code adherence to design specifications
// (such as text scaling prohibitions and touch target standards).
type DesignSystemRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (DesignSystemRule) Name() string {
	return "design-system-spec"
}

func (r DesignSystemRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	// Anti-pattern: disabling text scaling in an app where design system mandates dynamic text scaling
	disabledTextScalingRe = regexp.MustCompile(
		`\b(?:textScaler:\s*TextScaler\.noScaling|allowFontScaling:\s*false|textScaleFactor:\s*1\.0\b)`,
	)
)

func (r DesignSystemRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	spec := r.loadDesignSystemSpec()
	if !spec.hasDynamicTextScaling {
		return nil
	}

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if !isUIFile(filePath) || isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		for _, block := range blocks {
			lines := strings.Split(block.text, "\n")
			for i, line := range lines {
				lineNum := block.firstLine + i
				if !block.addedLines[lineNum] && len(block.addedLines) > 0 {
					continue
				}

				if disabledTextScalingRe.MatchString(line) {
					key := fmt.Sprintf("%s:%d", block.file, lineNum)
					if seen[key] {
						continue
					}
					seen[key] = true

					msg := "Dynamic text scaling disabled in UI; violates repository accessibility design system"
					remediation := "Allow system text scaling (up to 200%) using flexible layouts and auto-wrapping text containers."
					if spec.textScalingCitation != "" {
						remediation += " Adheres to " + spec.textScalingCitation + "."
					}

					finding := Finding{
						Rule:        "design-system-spec",
						Severity:    "medium",
						Category:    "quality",
						File:        block.file,
						Line:        lineNum,
						Message:     msg,
						Remediation: remediation,
						Confidence:  "High",
						Explanation: &model.FindingExplanation{
							RuleRationale:   "Design systems require accessible text scaling for visually impaired users.",
							EvidenceSummary: "Explicitly disabled text scaling detected in UI code.",
							EvidenceKind:    "spec-contract",
							EvidenceSteps: []model.ExplainedStep{
								{
									StepNumber: 1,
									Kind:       "source",
									Location:   fmt.Sprintf("%s:%d", block.file, lineNum),
									Statement:  "Text scaling override disables system font scaling",
								},
								{
									StepNumber: 2,
									Kind:       "sink",
									Statement:  "Violates design system dynamic text scaling specification",
								},
							},
						},
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

type designSystemSpec struct {
	hasDynamicTextScaling bool
	textScalingCitation   string
}

func (r DesignSystemRule) loadDesignSystemSpec() designSystemSpec {
	if r.RepositoryRoot == "" {
		return designSystemSpec{}
	}

	candidates := []string{
		"design_system",
		"docs/design",
		"design-system",
	}

	var spec designSystemSpec
	textScalingRe := regexp.MustCompile(`(?i)(?:text scaling|dynamic text|font size.*200%|2\.0x)`)

	for _, dirName := range candidates {
		dir := filepath.Join(r.RepositoryRoot, dirName)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".md") {
				docPath := filepath.Join(dir, entry.Name())
				data, err := os.ReadFile(docPath)
				if err != nil {
					continue
				}
				lines := strings.Split(string(data), "\n")
				for idx, l := range lines {
					if textScalingRe.MatchString(l) {
						spec.hasDynamicTextScaling = true
						rel, err := filepath.Rel(r.RepositoryRoot, docPath)
						if err != nil {
							rel = docPath
						}
						spec.textScalingCitation = fmt.Sprintf("%s:%d", filepath.ToSlash(rel), idx+1)
						break
					}
				}
			}
		}
	}

	return spec
}
