package slop

import "github.com/jakej985-rgb/m3tal-review/internal/review/model"

const FileDeleted = "deleted"

type Finding = model.Finding

// FileDiff is the source context the analyzer needs for one changed file.
type FileDiff struct {
	Path        string
	ChangeType  string
	AddedLines  []int
	AddedText   map[int]string
	ContextText map[int]string
	Source      string // Complete content when the diff includes a newly added file.
}
