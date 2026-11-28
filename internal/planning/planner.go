package planning

import (
	"fmt"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/detection/buildsystem"
	"github.com/jakej985-rgb/m3tal-review/internal/detection/framework"
	"github.com/jakej985-rgb/m3tal-review/internal/detection/language"
)

// PlanConfig controls how the planner filters analyzers.
type PlanConfig struct {
	Profile           string
	LanguageFilter    []string
	DisabledAnalyzers []string
}

// PlannedAnalyzer represents an analyzer selected to run with its rationale.
type PlannedAnalyzer struct {
	Analyzer AnalyzerMetadata `json:"analyzer"`
	Reason   string           `json:"reason"`
}

// SkippedAnalyzer represents an analyzer omitted from the run with its rationale.
type SkippedAnalyzer struct {
	Analyzer AnalyzerMetadata `json:"analyzer"`
	Reason   string           `json:"reason"`
}

// ExecutionPlan is the explainable plan produced by the analysis planner.
type ExecutionPlan struct {
	Selected        []PlannedAnalyzer `json:"selected"`
	Skipped         []SkippedAnalyzer `json:"skipped"`
	SemanticSupport map[string]string `json:"semantic_support"`
}

// BuildPlan selects applicable analyzers based on repository detection, frameworks, build systems, and config.
func BuildPlan(det language.RepositoryDetection, frameworks []framework.FrameworkInfo, buildSystems []buildsystem.BuildSystemInfo, cfg PlanConfig, catalog []AnalyzerMetadata) ExecutionPlan {
	detectedLangs := make(map[string]int, len(det.Languages))
	for _, l := range det.Languages {
		detectedLangs[strings.ToLower(l.Name)] = l.FileCount
	}
	detectedFW := make(map[string]framework.FrameworkInfo, len(frameworks))
	for _, fw := range frameworks {
		detectedFW[strings.ToLower(fw.Name)] = fw
	}
	buildNames := make([]string, 0, len(buildSystems))
	for _, bs := range buildSystems {
		buildNames = append(buildNames, bs.Name)
	}

	langFilter := make(map[string]bool, len(cfg.LanguageFilter))
	for _, lf := range cfg.LanguageFilter {
		if t := strings.TrimSpace(strings.ToLower(lf)); t != "" {
			langFilter[t] = true
		}
	}
	disabled := make(map[string]bool, len(cfg.DisabledAnalyzers))
	for _, d := range cfg.DisabledAnalyzers {
		disabled[d] = true
	}

	profile := strings.ToLower(strings.TrimSpace(cfg.Profile))
	if profile == "" {
		profile = "fast"
	}

	plan := ExecutionPlan{
		SemanticSupport: make(map[string]string),
	}

	capMatrix := make(map[string]language.LanguageCapability)
	for _, c := range language.SupportedLanguages() {
		capMatrix[strings.ToLower(c.Name)] = c
	}
	for _, l := range det.Languages {
		if c, ok := capMatrix[strings.ToLower(l.Name)]; ok && c.Semantic {
			plan.SemanticSupport[l.Name] = "supported"
		} else {
			plan.SemanticSupport[l.Name] = "pending"
		}
	}

	for _, a := range catalog {
		if disabled[a.ID] {
			plan.Skipped = append(plan.Skipped, SkippedAnalyzer{Analyzer: a, Reason: "disabled by configuration"})
			continue
		}
		if len(a.Profiles) > 0 && !containsIgnoreCase(a.Profiles, profile) {
			plan.Skipped = append(plan.Skipped, SkippedAnalyzer{
				Analyzer: a,
				Reason:   fmt.Sprintf("not enabled for profile %q (requires %s)", profile, strings.Join(a.Profiles, ", ")),
			})
			continue
		}
		if len(langFilter) > 0 && len(a.Languages) > 0 && !matchesAnyIgnoreCase(a.Languages, langFilter) {
			plan.Skipped = append(plan.Skipped, SkippedAnalyzer{
				Analyzer: a,
				Reason:   "excluded by --language filter",
			})
			continue
		}

		switch a.Kind {
		case KindLanguage, KindSemantic:
			matchedLang := ""
			count := 0
			for _, lang := range a.Languages {
				if n := detectedLangs[strings.ToLower(lang)]; n > 0 {
					matchedLang = lang
					count += n
				}
			}
			if count == 0 {
				plan.Skipped = append(plan.Skipped, SkippedAnalyzer{
					Analyzer: a,
					Reason:   fmt.Sprintf("no %s files detected", strings.Join(a.Languages, "/")),
				})
				continue
			}
			plan.Selected = append(plan.Selected, PlannedAnalyzer{
				Analyzer: a,
				Reason:   fmt.Sprintf("detected %d %s file(s)", count, matchedLang),
			})

		case KindFramework, KindInfrastructure:
			matchedFW := ""
			for _, fw := range a.Frameworks {
				if _, ok := detectedFW[strings.ToLower(fw)]; ok {
					matchedFW = fw
					break
				}
			}
			if matchedFW == "" {
				plan.Skipped = append(plan.Skipped, SkippedAnalyzer{
					Analyzer: a,
					Reason:   fmt.Sprintf("%s not detected", strings.Join(a.Frameworks, "/")),
				})
				continue
			}
			plan.Selected = append(plan.Selected, PlannedAnalyzer{
				Analyzer: a,
				Reason:   fmt.Sprintf("detected %s", matchedFW),
			})

		default:
			if containsIgnoreCase(a.Capabilities, "dependencies") {
				if len(buildNames) == 0 {
					plan.Skipped = append(plan.Skipped, SkippedAnalyzer{
						Analyzer: a,
						Reason:   "no package/build manifest detected",
					})
					continue
				}
				plan.Selected = append(plan.Selected, PlannedAnalyzer{
					Analyzer: a,
					Reason:   fmt.Sprintf("detected build system(s): %s", strings.Join(buildNames, ", ")),
				})
				continue
			}
			plan.Selected = append(plan.Selected, PlannedAnalyzer{
				Analyzer: a,
				Reason:   fmt.Sprintf("enabled for profile %q", profile),
			})
		}
	}

	return plan
}

func containsIgnoreCase(list []string, target string) bool {
	for _, item := range list {
		if strings.EqualFold(item, target) {
			return true
		}
	}
	return false
}

func matchesAnyIgnoreCase(list []string, set map[string]bool) bool {
	for _, item := range list {
		if set[strings.ToLower(item)] {
			return true
		}
	}
	return false
}
