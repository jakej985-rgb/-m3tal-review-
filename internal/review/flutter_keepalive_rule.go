package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// FlutterKeepAliveRule detects stateful widgets holding interactive controllers
// or scroll toggles within scrollable views that omit AutomaticKeepAliveClientMixin.
// Without this mixin, ListView and CustomScrollView recycling destroys and resets
// stateful controls (like text drafts and autoscroll toggles) when scrolled offscreen.
type FlutterKeepAliveRule struct {
	ruleRuntime
}

func (FlutterKeepAliveRule) Name() string {
	return "flutter-listview-unpreserved-state"
}

var (
	flutterDartUIFileRe = regexp.MustCompile(`(?i)(?:screen|widget|view|panel|terminal|page).*\.dart$`)

	// stateClassDeclRe matches state class declarations and captures (1: stateClassName, 2: widgetName, 3: mixins)
	stateClassDeclRe = regexp.MustCompile(`class\s+(_?\w+State)\s+extends\s+(?:State|ConsumerState)<([a-zA-Z0-9_]+)>(?:\s+with\s+([^{]+))?\s*\{`)

	// interactiveControllerOrToggleRe matches presence of controllers or autoScroll toggles
	interactiveControllerOrToggleRe = regexp.MustCompile(`\b(?:_?autoScroll\b|_?commandController\b|TextEditingController\b)`)

	// scrollableOrRecycledRe detects evidence of scrollable/terminal recycling context
	scrollableOrRecycledRe = regexp.MustCompile(`(?i)(?:ListView|CustomScrollView|ScrollController|terminal|serial|console)`)

	// buildsScrollableRe detects if the widget itself builds/owns a scrollable list (so it's the container, not a recycled item)
	buildsScrollableRe = regexp.MustCompile(`(?i)\b(?:return\s+|=>\s*|child:\s*|body:\s*)(?:ListView|CustomScrollView|GridView)\b`)

	// recycledItemNameRe identifies item/row/tile widgets
	recycledItemNameRe = regexp.MustCompile(`(?i)\b\w*(?:Row|Item|Tile|Entry|Card|Cell|Draft)\w*State\b`)
)

func (r FlutterKeepAliveRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r FlutterKeepAliveRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !flutterDartUIFileRe.MatchString(block.file) || isTestFile(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		// Quick check: must have interactive controller/toggle and scrollable context
		if !interactiveControllerOrToggleRe.MatchString(scanText) || !scrollableOrRecycledRe.MatchString(scanText) {
			continue
		}

		matches := stateClassDeclRe.FindAllStringSubmatchIndex(scanText, -1)
		for _, m := range matches {
			stateClassName := scanText[m[2]:m[3]]
			widgetName := scanText[m[4]:m[5]]
			// Top-level screens and pages are route containers, not items recycled inside lists
			if strings.HasSuffix(stateClassName, "ScreenState") || strings.HasSuffix(stateClassName, "PageState") {
				continue
			}

			mixins := ""
			if m[6] != -1 && m[7] != -1 {
				mixins = scanText[m[6]:m[7]]
			}

			// If it already mixes in AutomaticKeepAliveClientMixin, skip
			if strings.Contains(mixins, "AutomaticKeepAliveClientMixin") {
				continue
			}

			// Find body bounds using balanced braces
			braceStart := m[1] - 1
			classBody := extractMethodBody(scanText, braceStart)

			// If this widget itself builds/returns the scrollable list, it is the list owner, not a recycled child
			if buildsScrollableRe.MatchString(classBody) {
				continue
			}

			// Check if this class body has interactive controller or toggle
			if !interactiveControllerOrToggleRe.MatchString(classBody) {
				continue
			}

			// Must have evidence that this widget is a child/item in a recycling scrollable:
			// e.g. named as an Item/Row/Tile/Entry or instantiated in an itemBuilder
			isRecycledItemName := recycledItemNameRe.MatchString(stateClassName)
			itemBuilderRe := regexp.MustCompile(`\bitemBuilder\s*:[^;]*\b` + regexp.QuoteMeta(widgetName) + `\b`)
			isInstantiatedAsChild := itemBuilderRe.MatchString(scanText)

			if !isRecycledItemName && !isInstantiatedAsChild {
				continue
			}

			lineNum := startLine + strings.Count(scanText[:m[0]], "\n")
			if len(block.addedLines) > 0 && !block.addedLines[lineNum] {
				continue
			}

			key := block.file + ":" + strconv.Itoa(lineNum)
			if !seen[key] {
				seen[key] = true
				findings = append(findings, Finding{
					Rule:        "flutter-listview-unpreserved-state",
					Severity:    "medium",
					File:        block.file,
					Line:        lineNum,
					Message:     "Stateful widget with interactive controllers or scroll toggles inside scrollable view omits AutomaticKeepAliveClientMixin",
					Remediation: "Mix in AutomaticKeepAliveClientMixin, implement 'bool get wantKeepAlive => true', and call super.build(context) to preserve controller and toggle states across ListView recycling.",
				})
			}
		}
	}

	return findings
}
