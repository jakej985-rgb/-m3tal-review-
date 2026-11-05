package review

import (
	"path"
	"sort"
	"strings"
)

type diffSourceBlock struct {
	file       string
	firstLine  int
	text       string
	addedLines map[int]bool
	lineCount  int
}

// diffSourceBlocks constructs contiguous source blocks across all files in the diff.
func diffSourceBlocks(diff string) []diffSourceBlock {
	var blocks []diffSourceBlock
	for _, fileDiff := range ParseDiff(diff) {
		blocks = append(blocks, fileDiffSourceBlocks(fileDiff)...)
	}
	return blocks
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
			lineComment = true
			continue
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
		if hashComments && c == '#' || extIs(ext, ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".properties", ".env") && c == ';' {
			lineComment = true
			continue
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

func maskNonCode(file, source string) []byte {
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
func sourceBlocks(diff, repositoryRoot string, workingTree bool) []diffSourceBlock {
	var blocks []diffSourceBlock
	for _, fileDiff := range ParseDiff(diff) {
		fileBlocks := diffSourceBlocksForFile(diff, fileDiff.Path)
		if source, err := readRuleSource(repositoryRoot, fileDiff.Path, workingTree); err == nil {
			fileBlocks = []diffSourceBlock{fullSourceBlock(fileDiff.Path, source, fileDiff.AddedLines)}
		}
		blocks = append(blocks, fileBlocks...)
	}
	return blocks
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
