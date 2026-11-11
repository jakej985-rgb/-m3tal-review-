package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// auditFindingCache memoizes per-file engine results across audit runs.
// Findings are cached BEFORE ApplyFindingFilters, so policy/ignore/baseline
// changes always take effect on the next run.
//
// The cache key covers the file diff, the sorted rule names, and a schema
// version. Bump auditCacheSchema whenever rule patterns change semantics;
// stale entries are simply ignored (they never produce wrong output, only
// missed cache hits) because the key includes the schema.
const auditCacheSchema = "10"

const auditCacheMaxBytes = 8 << 20 // skip caching very large file diffs
const auditCacheMaxEntries = 20000 // bound memory/disk use

type auditCache struct {
	mu      sync.Mutex
	path    string
	ruleKey string
	data    map[string][]review.Finding
	dirty   bool
}

func newAuditCache(repositoryRoot string, rules []review.Rule, enabled bool) *auditCache {
	if !enabled {
		return nil
	}
	if os.Getenv("M3TAL_NO_AUDIT_CACHE") != "" {
		return nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return nil
	}
	rootSum := sha256.Sum256([]byte(repositoryRoot))
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		names = append(names, r.Name())
	}
	sort.Strings(names)
	ruleSum := sha256.Sum256([]byte(strings.Join(names, "\x00") + "\x00" + auditCacheSchema))
	dir := filepath.Join(base, "m3tal-review", hex.EncodeToString(rootSum[:8]))
	c := &auditCache{
		path:    filepath.Join(dir, "audit-"+hex.EncodeToString(ruleSum[:8])+".json"),
		ruleKey: hex.EncodeToString(ruleSum[:]),
		data:    map[string][]review.Finding{},
	}
	if raw, err := os.ReadFile(c.path); err == nil && len(raw) <= 64<<20 {
		_ = json.Unmarshal(raw, &c.data)
	}
	return c
}

func (c *auditCache) get(fileDiff string) ([]review.Finding, bool) {
	if c == nil {
		return nil, false
	}
	sum := sha256.Sum256([]byte(fileDiff))
	key := hex.EncodeToString(sum[:])
	c.mu.Lock()
	defer c.mu.Unlock()
	f, ok := c.data[key]
	if !ok {
		return nil, false
	}
	out := make([]review.Finding, len(f))
	copy(out, f)
	return out, true
}

func (c *auditCache) put(fileDiff string, findings []review.Finding) {
	if c == nil || len(fileDiff) > auditCacheMaxBytes {
		return
	}
	sum := sha256.Sum256([]byte(fileDiff))
	key := hex.EncodeToString(sum[:])
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.data) >= auditCacheMaxEntries {
		return
	}
	// Timeout findings are timing-dependent; never cache them.
	for _, f := range findings {
		if strings.HasSuffix(f.Rule, "-timeout") {
			return
		}
	}
	c.data[key] = findings
	c.dirty = true
}

func (c *auditCache) flush() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if !c.dirty {
		c.mu.Unlock()
		return
	}
	c.dirty = false
	c.mu.Unlock()
	data, err := json.Marshal(c.data)
	if err != nil || len(data) > 64<<20 {
		return
	}
	_ = os.MkdirAll(filepath.Dir(c.path), 0o755)
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, c.path)
}
