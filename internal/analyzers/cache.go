package analyzers

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// ResultCache memoizes analyzer results keyed on analyzer ID, version, config,
// file classifications, and file contents.
type ResultCache struct {
	mu      sync.RWMutex
	version string
	entries map[string][]review.Finding
}

// NewResultCache creates an in-memory incremental analyzer cache keyed by tool version.
func NewResultCache(version string) *ResultCache {
	return &ResultCache{
		version: version,
		entries: make(map[string][]review.Finding),
	}
}

func (c *ResultCache) key(analyzerID, configKey string, files []TargetFile) string {
	h := sha256.New()
	h.Write([]byte(c.version))
	h.Write([]byte{0})
	h.Write([]byte(analyzerID))
	h.Write([]byte{0})
	h.Write([]byte(configKey))
	h.Write([]byte{0})
	sorted := make([]TargetFile, len(files))
	copy(sorted, files)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	for _, f := range sorted {
		h.Write([]byte(f.Path))
		h.Write([]byte{0})
		h.Write([]byte(f.Language))
		h.Write([]byte{0})
		h.Write([]byte(strings.Join(f.Secondary, ",")))
		h.Write([]byte{0})
		h.Write([]byte(f.Content))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Get returns cached findings for the analyzer + config + file set if present.
func (c *ResultCache) Get(analyzerID, configKey string, files []TargetFile) ([]review.Finding, bool) {
	if c == nil {
		return nil, false
	}
	k := c.key(analyzerID, configKey, files)
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.entries[k]
	if !ok {
		return nil, false
	}
	out := make([]review.Finding, len(v))
	copy(out, v)
	return out, true
}

// Put stores findings for the analyzer + config + file set.
func (c *ResultCache) Put(analyzerID, configKey string, files []TargetFile, findings []review.Finding) {
	if c == nil {
		return
	}
	k := c.key(analyzerID, configKey, files)
	cp := make([]review.Finding, len(findings))
	copy(cp, findings)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[k] = cp
}
