package review

import "github.com/jakej985-rgb/m3tal-review/internal/review/fsutil"

// fsOps is kept as an alias so existing report/history call sites and tests
// continue to inject filesystem operations.
type fsOps = fsutil.Ops

func defaultFSOps() fsutil.Ops {
	return fsutil.Default()
}
