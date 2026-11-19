package arch

import (
	"fmt"
	"path/filepath"
	"strings"
)

// DefaultPolicy returns a baseline layered architectural policy for the repository.
func DefaultPolicy() ArchitecturePolicy {
	return ArchitecturePolicy{
		Version: "1.0",
		Rules: []LayerRule{
			{
				Name:           "semantic-isolation",
				PackagePattern: "internal/semantic*",
				ForbiddenImports: []string{
					"internal/analysis*",
					"internal/review*",
					"cmd*",
				},
				Description: "Semantic IR must remain self-contained without higher layer imports.",
			},
			{
				Name:           "analysis-isolation",
				PackagePattern: "internal/analysis*",
				ForbiddenImports: []string{
					"internal/review*",
					"cmd*",
				},
				Description: "Analysis engines must not import review pipeline or CLI layers.",
			},
			{
				Name:           "review-isolation",
				PackagePattern: "internal/review*",
				ForbiddenImports: []string{
					"cmd*",
				},
				Description: "Review pipeline core must not import command entrypoints.",
			},
		},
	}
}

// patternMatches tests whether a package path matches a glob or prefix pattern.
func patternMatches(pkg, pattern string) bool {
	if pattern == "*" || pattern == pkg {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(pkg, prefix)
	}
	matched, err := filepath.Match(pattern, pkg)
	return err == nil && matched
}

func checkNodeRule(fromPkg string, node *PackageNode, rule LayerRule) []BoundaryViolation {
	var list []BoundaryViolation
	for _, edge := range node.Imports {
		if edge.ToPkg == fromPkg {
			continue
		}
		for _, forbidden := range rule.ForbiddenImports {
			if !patternMatches(edge.ToPkg, forbidden) {
				continue
			}
			msg := fmt.Sprintf(
				"Architectural boundary violation: package %s imports %s (rule: %s: %s)",
				fromPkg, edge.ToPkg, rule.Name, rule.Description,
			)
			list = append(list, BoundaryViolation{
				EdgeLocation: EdgeLocation{
					FromPkg: fromPkg,
					ToPkg:   edge.ToPkg,
					File:    edge.File,
					Line:    edge.Line,
				},
				RuleName: rule.Name,
				Message:  msg,
			})
		}
	}
	return list
}

// CheckPolicy evaluates an ArchitectureGraph against layer rules, reporting violations.
func CheckPolicy(graph *ArchitectureGraph, policy ArchitecturePolicy) []BoundaryViolation {
	if graph == nil || len(graph.Nodes) == 0 {
		return nil
	}

	var violations []BoundaryViolation
	for fromPkg, node := range graph.Nodes {
		for _, rule := range policy.Rules {
			if patternMatches(fromPkg, rule.PackagePattern) {
				violations = append(violations, checkNodeRule(fromPkg, node, rule)...)
			}
		}
	}
	return violations
}
