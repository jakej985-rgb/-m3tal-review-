package review

import (
	"context"
	"regexp"
	"strconv"

	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
)

// SQLiRule flags database queries built with string formatting or
// concatenation, the classic SQL injection shape.
type SQLiRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (SQLiRule) Name() string {
	return "sql-injection"
}

// sqliPatterns with raw=true must run against the unmasked block text because
// they need to see string delimiters (f-strings, template literals) that
// maskNonCode blanks out; the codeMask gate still excludes comments and
// string contents from matching.
var sqliPatterns = []struct {
	language language.CodeLanguage
	pattern  *regexp.Regexp
	raw      bool
	message  string
}{
	{
		language: language.LanguageGo,
		pattern: regexp.MustCompile(
			`\.(?:Query|QueryRow|Exec|QueryContext|ExecContext|Prepare|PrepareContext)\w*\s*` +
				`\((?:[^()]|\([^()]*\)){0,150}?(?:fmt\.Sprintf|\+\s*[A-Za-z_(])`),
		message: "SQL query built with fmt.Sprintf or concatenation; use parameterized queries",
	},
	{
		language: language.LanguagePython,
		pattern: regexp.MustCompile(
			`\.execute(?:many|script)?\s*\(\s*[^)]{0,120}?(?:\.format\s*\(|%\s*\(?[\w(]|\+\s*\w)`),
		message: "SQL query built with string formatting; use parameterized queries",
	},
	{
		language: language.LanguagePython,
		pattern:  regexp.MustCompile(`\.execute(?:many|script)?\s*\(\s*f["']`),
		raw:      true,
		message:  "SQL query built with an f-string; use parameterized queries",
	},
	{
		language: language.LanguageJavaScript,
		pattern:  regexp.MustCompile(`\.(?:query|execute)\w*\s*\([^)]{0,120}?\+\s*\w`),
		message:  "SQL query built with concatenation; use parameterized queries",
	},
	{
		language: language.LanguageTypeScript,
		pattern:  regexp.MustCompile(`\.(?:query|execute)\w*\s*\([^)]{0,120}?\+\s*\w`),
		message:  "SQL query built with concatenation; use parameterized queries",
	},
	{
		language: language.LanguageJavaScript,
		pattern:  regexp.MustCompile("\\.(?:query|execute)\\w*\\s*\\(\\s*`[^`]*\\$\\{"),
		raw:      true,
		message:  "SQL query built with template interpolation; use parameterized queries",
	},
	{
		language: language.LanguageTypeScript,
		pattern:  regexp.MustCompile("\\.(?:query|execute)\\w*\\s*\\(\\s*`[^`]*\\$\\{"),
		raw:      true,
		message:  "SQL query built with template interpolation; use parameterized queries",
	},
	{
		language: language.LanguageCSharp,
		pattern:  regexp.MustCompile(`\.(?:FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync)\s*\(\s*(?:\$|[^,)]*?\+)`),
		raw:      true,
		message:  "EF Core raw SQL executed with interpolated string or concatenation; use FromSqlInterpolated or parameterized queries",
	},
	{
		language: language.LanguageCSharp,
		pattern:  regexp.MustCompile(`new\s+SqlCommand\s*\(\s*(?:\$|[^,)]*?\+)`),
		raw:      true,
		message:  "SqlCommand constructed with string interpolation or concatenation; use SqlParameter",
	},
	{
		language: language.LanguageJava,
		pattern:  regexp.MustCompile(`\.(?:createQuery|createNativeQuery|prepareCall|prepareStatement|executeQuery|executeUpdate)\s*\([^;\n]{0,180}?(?:\+|String\.format|formatted\()`),
		message:  "SQL/HQL query built with concatenation or formatting; use parameterized queries",
	},
	{
		language: language.LanguageKotlin,
		pattern:  regexp.MustCompile(`\.(?:createQuery|createNativeQuery|prepareCall|prepareStatement|executeQuery|executeUpdate)\s*\([^;\n]{0,180}?(?:\+|"\s*\$\{)`),
		raw:      true,
		message:  "SQL query built with string interpolation or concatenation; use parameterized queries",
	},
	{
		language: language.LanguagePHP,
		pattern:  regexp.MustCompile(`\b(?:query|prepare|exec)\s*\([^;)]*?(?:\.\s*\$[a-zA-Z_\x7f-\xff]|"[^"]*\$[a-zA-Z_\x7f-\xff])`),
		raw:      true,
		message:  "PDO/mysqli query built with concatenation or interpolation; use parameterized prepared statements",
	},
	{
		language: language.LanguagePHP,
		pattern:  regexp.MustCompile(`(?:DB::|->)\s*(?:raw|whereRaw|havingRaw|selectRaw|orderByRaw|groupByRaw)\s*\([^;)]*?(?:\.\s*\$[a-zA-Z_\x7f-\xff]|"[^"]*\$[a-zA-Z_\x7f-\xff])`),
		raw:      true,
		message:  "Laravel raw query built with variable concatenation or interpolation; pass bindings as second argument",
	},
}

func (r SQLiRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r SQLiRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		fileLanguage := (language.CodeChecker{}).Language(block.file)
		code := string(maskNonCode(block.file, block.text))
		codeMask := sourceCodeMask(block.file, block.text)
		for _, sqliPattern := range sqliPatterns {
			if sqliPattern.language != fileLanguage {
				continue
			}
			search := code
			if sqliPattern.raw {
				search = block.text
			}
			for _, match := range sqliPattern.pattern.FindAllStringIndex(search, -1) {
				if sqliPattern.raw && (match[0] >= len(codeMask) || !codeMask[match[0]]) {
					continue
				}
				if !matchTouchesAdded(block, search, match[0], match[1]) {
					continue
				}
				line := lineAtOffset(block.firstLine, search, match[0])
				key := block.file + ":" + strconv.Itoa(line)
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, Finding{
					Rule:        "sql-injection",
					Severity:    "high",
					File:        block.file,
					Line:        line,
					Message:     sqliPattern.message,
					Remediation: "Use parameterized queries or an ORM; never interpolate user input into SQL.",
				})
			}
		}
	}
	return findings
}
