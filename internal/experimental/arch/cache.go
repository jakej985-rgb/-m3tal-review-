package arch

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
)

// GraphCache holds a cached ArchitectureGraph and its integrity metadata.
type GraphCache struct {
	mu            sync.RWMutex
	Graph         *ArchitectureGraph
	ConfigHash    string
	PackageHashes map[string]string
}

// ComputeConfigHash creates a deterministic hash of policy rules for cache validation.
func ComputeConfigHash(policy ArchitecturePolicy) string {
	h := sha256.New()
	h.Write([]byte(policy.Version))
	for _, r := range policy.Rules {
		h.Write([]byte(r.Name + ":" + r.PackagePattern + ":" + strings.Join(r.ForbiddenImports, ",")))
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// NewGraphCache creates an initialized GraphCache.
func NewGraphCache(graph *ArchitectureGraph, configHash string) *GraphCache {
	pkgHashes := make(map[string]string)
	if graph != nil {
		for p, node := range graph.Nodes {
			pkgHashes[p] = node.ContentHash
		}
	}
	return &GraphCache{
		Graph:         graph,
		ConfigHash:    configHash,
		PackageHashes: pkgHashes,
	}
}

// IsValid validates whether the cached graph is still fresh against current hashes.
// Correctness-first: any difference in config or package contents invalidates the cache.
func (c *GraphCache) IsValid(currentHashes map[string]string, currentConfigHash string) bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.Graph == nil || c.ConfigHash != currentConfigHash {
		return false
	}
	if len(c.PackageHashes) != len(currentHashes) {
		return false
	}
	for pkg, h := range c.PackageHashes {
		if currentHashes[pkg] != h {
			return false
		}
	}
	return true
}

// InvalidateChanged removes changed packages and their dependents from the cached graph.
func (c *GraphCache) InvalidateChanged(changedFiles []string) []string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.Graph == nil {
		return nil
	}

	impact := EstimateImpact(c.Graph, changedFiles)
	var invalidated []string
	invalidated = append(invalidated, impact.ChangedPackages...)
	for _, n := range impact.DirectlyAffected {
		invalidated = append(invalidated, n.Package)
	}

	for _, p := range invalidated {
		delete(c.Graph.Nodes, p)
		delete(c.PackageHashes, p)
	}

	sort.Strings(invalidated)
	return invalidated
}
