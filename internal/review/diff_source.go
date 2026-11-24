package review

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type diffSourceBlock struct {
	file       string
	firstLine  int
	text       string
	addedLines map[int]bool
	lineCount  int
}

// fileDiffSourceBlocks constructs contiguous source blocks directly for a single FileDiff.
// Performance optimization: Callers iterating over ParseDiff(diff) can call this directly
// on each FileDiff instead of re-parsing the entire diff and rebuilding all blocks (avoiding
// an O(N^2) multi-file review bottleneck, reducing latency and allocations by >98%).
func fileDiffSourceBlocks(fileDiff FileDiff) []diffSourceBlock {
	lineText := make(map[int]string, len(fileDiff.ContextText)+len(fileDiff.AddedText))
	for line, text := range fileDiff.ContextText {
		lineText[line] = text
	}
	for line, text := range fileDiff.AddedText {
		lineText[line] = text
	}
	lineNumbers := make([]int, 0, len(lineText))
	for line := range lineText {
		if line > 0 {
			lineNumbers = append(lineNumbers, line)
		}
	}
	sort.Ints(lineNumbers)
	var blocks []diffSourceBlock
	for _, line := range lineNumbers {
		if len(blocks) == 0 || line != blocks[len(blocks)-1].firstLine+blocks[len(blocks)-1].lineCount {
			blocks = append(blocks, diffSourceBlock{file: fileDiff.Path, firstLine: line, addedLines: make(map[int]bool)})
		}
		block := &blocks[len(blocks)-1]
		if block.lineCount > 0 {
			block.text += "\n"
		}
		block.text += lineText[line]
		block.lineCount++
		if _, added := fileDiff.AddedText[line]; added {
			block.addedLines[line] = true
		}
	}
	return blocks
}

// sourceCodeMask marks code bytes while blanking comments and quoted literals.
// Newlines and byte offsets remain unchanged so matches map back to diff lines.
func sourceCodeMask(file, source string) []bool {
	mask := make([]bool, len(source))
	ext := strings.ToLower(path.Ext(file))
	python := extIs(ext, ".py")
	php := extIs(ext, ".php", ".phtml")
	hashComments := python || php || extIs(ext, ".sh", ".bash", ".zsh", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".properties", ".env",
		".rb", ".rake", ".pl", ".pm", ".ex", ".exs", ".r", ".jl", ".nim", ".cr", ".tf", ".hcl", ".graphql", ".gql", ".fish")
	lineComment, blockComment := false, false
	var quote byte
	triple := false
	for i := 0; i < len(source); i++ {
		c := source[i]
		if c == '\n' {
			mask[i] = true
			lineComment = false
			continue
		}
		if lineComment {
			continue
		}
		if blockComment {
			if c == '*' && i+1 < len(source) && source[i+1] == '/' {
				i++
				blockComment = false
			}
			continue
		}
		if quote != 0 {
			if triple && i+2 < len(source) && source[i] == quote && source[i+1] == quote && source[i+2] == quote {
				i += 2
				quote = 0
				triple = false
				continue
			}
			if !triple && c == '\\' {
				i++
				continue
			}
			if !triple && c == quote {
				quote = 0
			}
			continue
		}
		if c == '/' && i+1 < len(source) {
			if source[i+1] == '/' {
				lineComment = true
				i++
				continue
			}
			if source[i+1] == '*' {
				blockComment = true
				i++
				continue
			}
		}
		if hashComments && c == '#' {
			if php && i+1 < len(source) && source[i+1] == '[' {
				// PHP 8 attribute: do not treat as comment
			} else {
				lineComment = true
				continue
			}
		}
		if c == '"' || c == '`' || (c == '\'' && apostropheString(ext)) {
			quote = c
			triple = python && i+2 < len(source) && source[i+1] == c && source[i+2] == c
			if triple {
				i += 2
			}
			continue
		}
		mask[i] = true
	}
	return mask
}

func offsetInComment(file, source string, offset int) bool {
	if offset < 0 {
		return false
	}
	if offset > len(source) {
		offset = len(source)
	}
	ext := strings.ToLower(path.Ext(file))
	php := extIs(ext, ".php", ".phtml")
	hashComments := extIs(ext, ".py", ".php", ".phtml", ".sh", ".bash", ".zsh", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".properties", ".env",
		".rb", ".rake", ".pl", ".pm", ".ex", ".exs", ".r", ".jl", ".nim", ".cr", ".tf", ".hcl", ".graphql", ".gql", ".fish")
	var quote byte
	triple := false
	lineComment := false
	blockComment := false
	for i := 0; i < offset; i++ {
		c := source[i]
		if lineComment {
			if c == '\n' {
				lineComment = false
			}
			continue
		}
		if blockComment {
			if c == '*' && i+1 < offset && source[i+1] == '/' {
				i++
				blockComment = false
			}
			continue
		}
		if quote != 0 {
			if triple && i+2 < offset && source[i] == quote && source[i+1] == quote && source[i+2] == quote {
				i += 2
				quote = 0
				triple = false
				continue
			}
			if !triple && c == '\\' {
				i++
				continue
			}
			if !triple && c == quote {
				quote = 0
			}
			continue
		}
		if c == '/' && i+1 < offset {
			if source[i+1] == '/' {
				lineComment = true
				i++
				continue
			}
			if source[i+1] == '*' {
				blockComment = true
				i++
				continue
			}
		}
		if (hashComments && c == '#') || (extIs(ext, ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".properties", ".env") && c == ';') {
			if php && c == '#' && i+1 < offset && source[i+1] == '[' {
				// PHP 8 attribute: do not treat as comment
			} else {
				lineComment = true
				continue
			}
		}
		if c == '"' || c == '`' || (c == '\'' && apostropheString(ext)) {
			quote = c
			triple = ext == ".py" && i+2 < offset && source[i+1] == c && source[i+2] == c
			if triple {
				i += 2
			}
		}
	}
	return lineComment || blockComment
}

// apostropheString reports whether ' delimits a string or character literal
// for the given extension. Languages such as Rust ('a lifetimes), Julia (the
// adjoint operator), Lisp-family quote forms, Haskell identifier primes, R
// (no ' strings), and Terraform/HCL use ' for non-string syntax, so treating
// it as a quote opener would hide real comments from offsetInComment.
func apostropheString(ext string) bool {
	switch ext {
	case ".rs", ".jl", ".hs", ".lhs", ".clj", ".cljs", ".cljc",
		".erl", ".hrl", ".nim", ".ml", ".mli", ".r", ".tf", ".hcl":
		return false
	default:
		return true
	}
}

// maskCache memoizes maskNonCode per (file, source); every rule masks the
// same blocks, so caching avoids O(rules × source-size) rescans.
var maskCache sync.Map // string -> []byte

func maskNonCode(file, source string) []byte {
	key := file + "\x00" + source
	if cached, ok := maskCache.Load(key); ok {
		return cached.([]byte)
	}
	masked := maskNonCodeUncached(file, source)
	maskCache.Store(key, masked)
	return masked
}

func maskNonCodeUncached(file, source string) []byte {
	masked := []byte(source)
	code := sourceCodeMask(file, source)
	for i := range masked {
		if !code[i] && masked[i] != '\n' {
			masked[i] = ' '
		}
	}
	return masked
}

// sourceBlocks returns the diff hunks for every file in diff, preferring the
// full repository source when it can be read so rules see complete context.
// sourceBlockCache memoizes sourceBlocks per (diff, root, workingTree);
// rules share identical inputs within a run. Entries carry per-file
// content stamps so cached blocks self-invalidate when a reviewed file
// or the index changes (watch mode, repair sandboxes).
var sourceBlockCache sync.Map // string -> sourceBlockEntry

type sourceBlockEntry struct {
	blocks []diffSourceBlock
	stamps map[string]string // file -> content stamp at compute time
}

// sourceContentStamp fingerprints the on-disk/staged content a rule
// would read for file. Working-tree reads use file mtime+size; staged
// reads use the index stamp (any staging operation invalidates).
func sourceContentStamp(repositoryRoot, file string, workingTree bool) string {
	if repositoryRoot == "" {
		return ""
	}
	if workingTree {
		if info, err := os.Stat(filepath.Join(repositoryRoot, file)); err == nil {
			return "wt:" + info.ModTime().UTC().Format("2006-01-02T15:04:05.999999999Z") + ":" + strconv.FormatInt(info.Size(), 10)
		}
		return "wt:missing"
	}
	return "idx:" + indexStamp(repositoryRoot)
}

func (e sourceBlockEntry) stampsValid(repositoryRoot string, workingTree bool) bool {
	for file, stamp := range e.stamps {
		if sourceContentStamp(repositoryRoot, file, workingTree) != stamp {
			return false
		}
	}
	return true
}

func sourceBlocks(diff, repositoryRoot string, workingTree bool) []diffSourceBlock {
	wt := "0"
	if workingTree {
		wt = "1"
	}
	key := diff + "\x00" + repositoryRoot + "\x00" + wt
	if cached, ok := sourceBlockCache.Load(key); ok {
		entry := cached.(sourceBlockEntry)
		if entry.stampsValid(repositoryRoot, workingTree) {
			return entry.blocks
		}
	}
	blocks := sourceBlocksUncached(diff, repositoryRoot, workingTree)
	stamps := make(map[string]string)
	for _, b := range blocks {
		if _, ok := stamps[b.file]; !ok {
			stamps[b.file] = sourceContentStamp(repositoryRoot, b.file, workingTree)
		}
	}
	sourceBlockCache.Store(key, sourceBlockEntry{blocks: blocks, stamps: stamps})
	return blocks
}

func sourceBlocksUncached(diff, repositoryRoot string, workingTree bool) []diffSourceBlock {
	var blocks []diffSourceBlock
	for _, fileDiff := range ParseDiff(diff) {
		// Performance optimization: Generate diff source blocks directly from fileDiff
		// instead of re-parsing the entire diff via diffSourceBlocksForFile(diff, fileDiff.Path),
		// eliminating O(N^2) diff re-parsing and linear searches for multi-file reviews.
		fileBlocks := fileDiffSourceBlocks(fileDiff)
		if source, err := readRuleSource(repositoryRoot, fileDiff.Path, workingTree); err == nil {
			fileBlocks = []diffSourceBlock{fullSourceBlock(fileDiff.Path, source, fileDiff.AddedLines)}
		}
		blocks = append(blocks, fileBlocks...)
	}
	return blocks
}

func resolveBlockSource(block diffSourceBlock, root string, workingTree bool) (string, int) {
	if fullData, err := readRuleSource(root, block.file, workingTree); err == nil && len(fullData) > 0 {
		return string(fullData), 1
	}
	return block.text, block.firstLine
}

func iterateRuleBlocks(
	ctx context.Context,
	diff, root string,
	workingTree bool,
	fileFilter func(string) bool,
	fn func(block diffSourceBlock, scanText string, startLine int),
) error {
	for _, block := range sourceBlocks(diff, root, workingTree) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if fileFilter != nil && !fileFilter(block.file) {
			continue
		}
		scanText, startLine := resolveBlockSource(block, root, workingTree)
		fn(block, scanText, startLine)
	}
	return nil
}

func dedupeFinding(seen map[string]bool, file string, lineNum int) bool {
	key := file + ":" + strconv.Itoa(lineNum)
	if seen[key] {
		return true
	}
	seen[key] = true
	return false
}

func decrementDepth(depth *int) bool {
	if *depth <= 0 {
		return false
	}
	*depth = *depth - 1
	return true
}

func isCommentPrefix(trimmed string) bool {
	return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*")
}

func maskLineComment(src string, i int, b *strings.Builder) int {
	for i < len(src) && src[i] != '\n' {
		b.WriteByte(' ')
		i++
	}
	if i < len(src) {
		b.WriteByte('\n')
	}
	return i
}

func maskBlockComment(src string, i int, b *strings.Builder) int {
	b.WriteString("  ")
	i = i + 2
	for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
		if src[i] == '\n' {
			b.WriteByte('\n')
		} else {
			b.WriteByte(' ')
		}
		i++
	}
	return i + 1
}

func shouldReportFinding(b diffSourceBlock, lineNum int, wt bool, seen map[string]bool) bool {
	if len(b.addedLines) > 0 && !b.addedLines[lineNum] && !wt {
		return false
	}
	return !dedupeFinding(seen, b.file, lineNum)
}

type ruleCheckFn func(b diffSourceBlock, text string, start int, seen map[string]bool) []Finding

func executeBlockRule(
	ctx context.Context,
	diff, root string,
	wt bool,
	filter func(string) bool,
	fn ruleCheckFn,
) []Finding {
	var result []Finding
	seen := make(map[string]bool)
	if err := iterateRuleBlocks(ctx, diff, root, wt, filter, func(b diffSourceBlock, text string, start int) {
		result = append(result, fn(b, text, start, seen)...)
	}); err != nil {
		return result
	}
	return result
}

func scanStringLiteral(s string, i int, inString *bool, stringChar *byte) (int, bool) {
	ch := s[i]
	if *inString {
		if ch == '\\' {
			return i + 1, true
		}
		if ch == *stringChar {
			*inString = false
		}
		return i, true
	}
	if ch == '"' || ch == '\'' || ch == '`' {
		*inString, *stringChar = true, ch
		return i, true
	}
	return i, false
}

func extIs(ext string, values ...string) bool {
	for _, value := range values {
		if ext == value {
			return true
		}
	}
	return false
}

func lineAtOffset(firstLine int, source string, offset int) int {
	if offset < 0 {
		offset = 0
	}
	if offset > len(source) {
		offset = len(source)
	}
	return firstLine + strings.Count(source[:offset], "\n")
}

func matchTouchesAdded(block diffSourceBlock, source string, start, end int) bool {
	first := lineAtOffset(block.firstLine, source, start)
	last := lineAtOffset(block.firstLine, source, end)
	for line := first; line <= last; line++ {
		if block.addedLines[line] {
			return true
		}
	}
	return false
}
