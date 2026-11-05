package slop_test

import (
	"strings"
	"testing"

	review "github.com/jakej985-rgb/m3tal-review/internal/review"
)

func goFindings(t *testing.T, source string) []review.Finding {
	t.Helper()
	repo := setupSlopTestRepo(t, source)
	return (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff("main.go", source))
}

func hasMessage(findings []review.Finding, message string) bool {
	for _, f := range findings {
		if f.Message == message {
			return true
		}
	}
	return false
}

func TestGoElseAfterReturn(t *testing.T) {
	source := `package main
func f(x int) int {
	if x > 0 {
		return 1
	} else {
		return 2
	}
}`
	findings := goFindings(t, source)
	if !hasMessage(findings, "Else branch after a terminating statement") {
		t.Fatalf("want else-after-return finding, got %+v", findings)
	}
}

func TestGoElseAfterNonTerminatorAllowed(t *testing.T) {
	source := `package main
func f(x int) int {
	if x > 0 {
		println("pos")
	} else {
		return 2
	}
	return 0
}`
	findings := goFindings(t, source)
	if hasMessage(findings, "Else branch after a terminating statement") {
		t.Fatalf("else after non-terminating if should not be flagged: %+v", findings)
	}
}

func TestGoIfReturnBool(t *testing.T) {
	source := `package main
func f(x int) bool {
	if x > 0 {
		return true
	}
	return false
}
func g(x int) bool {
	if x > 0 {
		return true
	} else {
		return false
	}
}`
	findings := goFindings(t, source)
	count := 0
	for _, f := range findings {
		if f.Message == "If/else returns boolean literals" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("want 2 boolean-return findings, got %d: %+v", count, findings)
	}
}

func TestGoDeadCode(t *testing.T) {
	source := `package main
func f() int {
	return 1
	x := 2
	_ = x
	return 3
}`
	findings := goFindings(t, source)
	if !hasMessage(findings, "Unreachable code after terminating statement") {
		t.Fatalf("want dead-code finding, got %+v", findings)
	}
}

func TestGoDeadCodeFallthroughAllowed(t *testing.T) {
	source := `package main
func f(x int) int {
	switch x {
	case 1:
		return 1
	default:
		fallthrough
	case 2:
		return 2
	}
	return 0
}`
	findings := goFindings(t, source)
	if hasMessage(findings, "Unreachable code after terminating statement") {
		t.Fatalf("fallthrough should not count as terminating: %+v", findings)
	}
}

func TestGoIgnoredCallResult(t *testing.T) {
	source := `package main
func f() error { return nil }
func g() {
	_ = f()
	_, _ = f()
	x, _ := f()
	_ = x
}`
	findings := goFindings(t, source)
	count := 0
	for _, f := range findings {
		if f.Message == "Call result discarded with blank identifier" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("want 2 ignored-call findings (_= and _,_=), got %d: %+v", count, findings)
	}
}

func TestGoLongFunctionAndParams(t *testing.T) {
	var b strings.Builder
	b.WriteString("package main\nfunc many(a, b, c, d, e, f, g int) int {\n")
	for i := 0; i < 85; i++ {
		b.WriteString("\tx := 1\n\t_ = x\n")
	}
	b.WriteString("\treturn a\n}\n")
	findings := goFindings(t, b.String())
	if !hasMessage(findings, "Function exceeds 80 lines") {
		t.Fatalf("want long-function finding, got %+v", findings)
	}
	if !hasMessage(findings, "Function has many parameters (7)") {
		t.Fatalf("want many-params finding, got %+v", findings)
	}
}

func slopFindings(t *testing.T, name, source string) []review.Finding {
	t.Helper()
	repo := stageNonGoSlopSource(t, name, source)
	return (review.SlopRule{RepositoryRoot: repo}).Check(fullSourceDiff(name, source))
}

func TestJSSloppyEquality(t *testing.T) {
	source := `function f(a, b) {
	if (a == b) { return 1; }
	if (a != null) { return 2; }
	if (a === b) { return 3; }
	return 0;
}`
	findings := slopFindings(t, "main.js", source)
	count := 0
	for _, f := range findings {
		if f.Message == "Non-strict equality comparison" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("want exactly 1 non-strict finding (== null exempt), got %d: %+v", count, findings)
	}
}

func TestJSSloppyEqualityIgnoresStrings(t *testing.T) {
	source := `const s = "a == b";
// a == b
const t = 'x != y';
`
	findings := slopFindings(t, "main.js", source)
	if hasMessage(findings, "Non-strict equality comparison") {
		t.Fatalf("strings/comments produced non-strict findings: %+v", findings)
	}
}

func TestJSElseAfterReturnAndDeadCode(t *testing.T) {
	source := `function f(x) {
	if (x > 0) {
		return 1;
	} else {
		return 2;
	}
	return 0;
}
function g(x) {
	if (x) {
		return;
		console.log("dead");
	}
	return x;
}
function h(x) {
	if (x) return;
	console.log("reachable");
}`
	findings := slopFindings(t, "main.js", source)
	if !hasMessage(findings, "Else branch after a terminating statement") {
		t.Fatalf("want else-after-return: %+v", findings)
	}
	if !hasMessage(findings, "Unreachable code after terminating statement") {
		t.Fatalf("want dead-code finding: %+v", findings)
	}
}

func TestJSLongBooleanChain(t *testing.T) {
	source := `function f(a, b, c, d, e, g) {
	if (a && b && c && d && e && g) { return 1; }
	return 0;
}`
	findings := slopFindings(t, "main.js", source)
	if !hasMessage(findings, "Long boolean operator chain (5+ operators)") {
		t.Fatalf("want bool-chain finding, got %+v", findings)
	}
}

func TestJSSuppressionsAndCommentedCode(t *testing.T) {
	source := `// eslint-disable-next-line no-console
console.log("x");
// if (old) {
//     doThing();
// }
function ok() { return 1; }
`
	findings := slopFindings(t, "main.js", source)
	if !hasMessage(findings, "Lint suppression without justification") {
		t.Fatalf("want suppression finding, got %+v", findings)
	}
	if !hasMessage(findings, "Commented-out code") {
		t.Fatalf("want commented-out-code finding, got %+v", findings)
	}
}

func TestJSOrdinaryCommentsNotFlagged(t *testing.T) {
	source := `// Returns the computed value for the user.
// This is a longer explanatory comment about behavior.
// Note: see the docs for details.
function f() { return 1; }
`
	findings := slopFindings(t, "main.js", source)
	if hasMessage(findings, "Commented-out code") {
		t.Fatalf("prose comments flagged as code: %+v", findings)
	}
}

func TestDuplicateCodeBlocks(t *testing.T) {
	source := `function setup() {
	const client = createClient();
	client.setTimeout(5000);
	client.setRetries(3);
	client.setLogger(log);
	return client;
}
function teardown() {
	const client = createClient();
	client.setTimeout(5000);
	client.setRetries(3);
	client.setLogger(log);
	return client;
}`
	findings := slopFindings(t, "main.js", source)
	if !hasMessage(findings, "Duplicated code block") {
		t.Fatalf("want duplicate-block finding, got %+v", findings)
	}
}

func TestPythonMutableDefault(t *testing.T) {
	source := `def f(items=[], mapping={}, count=0):
    return items

def g(x: list = []):
    return x

def ok(items=None):
    return items or []
`
	findings := slopFindings(t, "main.py", source)
	count := 0
	for _, f := range findings {
		if f.Message == "Mutable default argument" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("want 2 mutable-default findings, got %d: %+v", count, findings)
	}
}

func TestPythonElseAfterReturnAndDeadCode(t *testing.T) {
	source := `def f(x):
    if x > 0:
        return 1
    else:
        return 2

def g(x):
    if x:
        return
        print("dead")
    return x

def h(x):
    for i in range(x):
        if i > 2:
            break
        else:
            continue
    return x
`
	findings := slopFindings(t, "main.py", source)
	if !hasMessage(findings, "Else branch after a terminating statement") {
		t.Fatalf("want else-after-return: %+v", findings)
	}
	if !hasMessage(findings, "Unreachable code after terminating statement") {
		t.Fatalf("want dead-code finding: %+v", findings)
	}
}

func TestPythonForElseNotFlagged(t *testing.T) {
	source := `def f(xs):
    for x in xs:
        if x:
            break
    else:
        print("done")
    return xs
`
	findings := slopFindings(t, "main.py", source)
	if hasMessage(findings, "Else branch after a terminating statement") {
		t.Fatalf("for-else should not be flagged: %+v", findings)
	}
}

func TestPythonBoolChainAndSuppressions(t *testing.T) {
	source := `def f(a, b, c, d, e, g):
    if a and b and c and d and e and g:  # noqa
        return True
    x = 1  # type: ignore
    return False
`
	findings := slopFindings(t, "main.py", source)
	if !hasMessage(findings, "Long boolean operator chain (5+ operators)") {
		t.Fatalf("want bool-chain finding: %+v", findings)
	}
	if !hasMessage(findings, "Lint suppression without justification") {
		t.Fatalf("want suppression finding: %+v", findings)
	}
}

func TestJSLogOnlyCatch(t *testing.T) {
	source := `function f() {
	try {
		risky();
	} catch (e) {
		console.error(e);
	}
	try {
		risky();
	} catch (e) {
		recover(e);
	}
}`
	findings := slopFindings(t, "main.js", source)
	count := 0
	for _, f := range findings {
		if f.Message == "Exception swallowed by log-only catch" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("want exactly 1 log-only-catch finding, got %d: %+v", count, findings)
	}
}

func TestJavaFlowFindings(t *testing.T) {
	source := `class A {
	int f(int x) {
		if (x > 0) {
			return 1;
		} else {
			return 2;
		}
	}
	void g() {
		try {
			return;
		} catch (Exception e) {
			return;
		}
	}
}`
	findings := slopFindings(t, "A.java", source)
	if !hasMessage(findings, "Else branch after a terminating statement") {
		t.Fatalf("want Java else-after-return: %+v", findings)
	}
	// try/catch after return must not be flagged.
	if hasMessage(findings, "Unreachable code after terminating statement") {
		t.Fatalf("catch after return should not be dead code: %+v", findings)
	}
}
