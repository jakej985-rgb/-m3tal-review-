package arch

import (
	"path/filepath"
	"sort"
	"strings"
)

// buildReverseGraph constructs an inverse dependency map (toPkg -> list of importing packages).
func buildReverseGraph(graph *ArchitectureGraph) map[string][]string {
	rev := make(map[string][]string)
	for fromPkg, node := range graph.Nodes {
		for _, imp := range node.Imports {
			rev[imp.ToPkg] = append(rev[imp.ToPkg], fromPkg)
		}
	}
	for k, list := range rev {
		seen := make(map[string]bool)
		var dedup []string
		for _, item := range list {
			if !seen[item] {
				seen[item] = true
				dedup = append(dedup, item)
			}
		}
		sort.Strings(dedup)
		rev[k] = dedup
	}
	return rev
}

func findChangedPackages(changedFiles []string) []string {
	pkgSet := make(map[string]bool)
	for _, f := range changedFiles {
		dir := filepath.Dir(f)
		if dir == "" {
			dir = "."
		}
		pkgSet[dir] = true
	}
	var pkgs []string
	for p := range pkgSet {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	return pkgs
}

type queueItem struct {
	pkg  string
	dist int
	via  string
}

func traverseImpactBFS(
	changedPkgs []string,
	revGraph map[string][]string,
) ([]ImpactNode, []ImpactNode) {
	var direct []ImpactNode
	var trans []ImpactNode
	visited := make(map[string]int)
	var queue []queueItem

	for _, p := range changedPkgs {
		visited[p] = 0
		for _, dep := range revGraph[p] {
			if _, seen := visited[dep]; !seen {
				visited[dep] = 1
				queue = append(queue, queueItem{pkg: dep, dist: 1, via: p})
			}
		}
	}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		node := ImpactNode{Package: curr.pkg, Distance: curr.dist, Via: curr.via}
		if curr.dist == 1 {
			node.Relation = ImpactExact
			direct = append(direct, node)
		} else {
			node.Relation = ImpactHeuristic
			trans = append(trans, node)
		}

		for _, next := range revGraph[curr.pkg] {
			if _, seen := visited[next]; !seen {
				visited[next] = curr.dist + 1
				queue = append(queue, queueItem{pkg: next, dist: curr.dist + 1, via: curr.pkg})
			}
		}
	}
	return direct, trans
}

func extractPackageTests(pNode *PackageNode) []string {
	if pNode == nil {
		return nil
	}
	var tests []string
	for _, file := range pNode.Files {
		if strings.HasSuffix(file, "_test.go") {
			tests = append(tests, file)
		}
	}
	return tests
}

func collectImpactTargets(
	graph *ArchitectureGraph,
	nodes []ImpactNode,
) ([]string, []string) {
	var analyzers []string
	var tests []string
	for _, n := range nodes {
		if strings.HasPrefix(n.Package, "internal/analysis") {
			analyzers = append(analyzers, filepath.Base(n.Package))
		}
		tests = append(tests, extractPackageTests(graph.Nodes[n.Package])...)
	}
	return analyzers, tests
}

// EstimateImpact computes the blast radius of changes across the repository graph.
func EstimateImpact(graph *ArchitectureGraph, changedFiles []string) ImpactEstimate {
	changedPkgs := findChangedPackages(changedFiles)
	if graph == nil || len(graph.Nodes) == 0 {
		return ImpactEstimate{
			ChangedFiles:    changedFiles,
			ChangedPackages: changedPkgs,
		}
	}

	revGraph := buildReverseGraph(graph)
	directNodes, transNodes := traverseImpactBFS(changedPkgs, revGraph)

	allNodes := append([]ImpactNode{}, directNodes...)
	allNodes = append(allNodes, transNodes...)
	analyzers, tests := collectImpactTargets(graph, allNodes)

	sort.Slice(directNodes, func(i, j int) bool {
		return directNodes[i].Package < directNodes[j].Package
	})
	sort.Slice(transNodes, func(i, j int) bool {
		return transNodes[i].Package < transNodes[j].Package
	})

	return ImpactEstimate{
		ChangedFiles:        changedFiles,
		ChangedPackages:     changedPkgs,
		DirectlyAffected:    directNodes,
		TransitivelyAffect:  transNodes,
		TotalAffectedCount:  len(directNodes) + len(transNodes),
		AffectedAnalyzers:   analyzers,
		AffectedTestTargets: tests,
	}
}
