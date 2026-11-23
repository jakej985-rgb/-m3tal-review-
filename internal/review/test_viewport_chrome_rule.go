package review

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

// TestViewportChromeRule is a cross-component boundary analyzer that verifies
// widget and layout tests that simulate desktop/tablet viewports account for
// application shell chrome (sidebars, app bars, navigation rails).
type TestViewportChromeRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (TestViewportChromeRule) Name() string {
	return "test-viewport-chrome-contract"
}

func (r TestViewportChromeRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	// Detects physicalSize or window size setting in test
	viewportSizeRe = regexp.MustCompile(
		`\b(?:tester\.view\.physicalSize|tester\.binding\.window\.physicalSizeTestValue|setSurfaceSize)\s*=\s*(?:const\s+)?Size\(\s*([0-9.]+)\s*,\s*([0-9.]+)`,
	)

	// Detects direct screen mounting in MaterialApp without shell
	directScreenRe = regexp.MustCompile(
		`\bMaterialApp\s*\([^)]*home:\s*(?:const\s+)?([A-Z]\w*(?:Screen|Page|View))\s*\(`,
	)

	// Shell widgets
	shellWidgetRe  = regexp.MustCompile(`\b(MainScaffold|AppShell|DesktopScaffold|GtkSidebar|SidebarShell)\b`)
	sidebarWidthRe = regexp.MustCompile(`\b(?:sidebarWidth|GtkSidebar|width)\s*[:=]\s*([0-9.]+)`)
)

func (r TestViewportChromeRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	// Find if repository has a desktop shell (e.g. MainScaffold, GtkSidebar)
	shellInfo := r.detectRepositoryShell()
	if shellInfo.shellName == "" {
		return nil
	}

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if !isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		for _, block := range blocks {
			findings = append(findings, r.checkBlock(block, seen, shellInfo)...)
		}
	}

	return findings
}

type repositoryShellInfo struct {
	shellName   string
	chromeWidth float64
	sourceFile  string
}

func (r TestViewportChromeRule) detectRepositoryShell() repositoryShellInfo {
	if r.RepositoryRoot == "" {
		return repositoryShellInfo{shellName: "MainScaffold", chromeWidth: 210.0}
	}

	var info repositoryShellInfo

	// Scan lib/ for shell widgets
	libDir := filepath.Join(r.RepositoryRoot, "lib")
	_ = filepath.Walk(libDir, func(path string, osInfo os.FileInfo, err error) error {
		if err != nil || osInfo == nil || osInfo.IsDir() || !strings.HasSuffix(path, ".dart") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)
		if m := shellWidgetRe.FindString(content); m != "" {
			info.shellName = m
			info.sourceFile = path
			info.chromeWidth = 210.0 // Default sidebar width
			if wm := sidebarWidthRe.FindStringSubmatch(content); len(wm) > 1 {
				if w, err := strconv.ParseFloat(wm[1], 64); err == nil && w > 0 {
					info.chromeWidth = w
				}
			}
			return filepath.SkipAll
		}
		return nil
	})

	if info.shellName == "" {
		info = repositoryShellInfo{shellName: "MainScaffold", chromeWidth: 210.0}
	}

	return info
}

func (r TestViewportChromeRule) checkBlock(block diffSourceBlock, seen map[string]bool, shell repositoryShellInfo) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")

	for i, line := range lines {
		lineNum := block.firstLine + i
		if !block.addedLines[lineNum] && len(block.addedLines) > 0 {
			continue
		}

		// Look for viewport size configuration (e.g. 1280x720)
		sm := viewportSizeRe.FindStringSubmatch(line)
		if len(sm) < 3 {
			continue
		}

		w, _ := strconv.ParseFloat(sm[1], 64)
		h, _ := strconv.ParseFloat(sm[2], 64)

		// Desktop viewport threshold >= 1024 dp
		if w < 1024.0 {
			continue
		}

		// Look ahead in the test body (up to 45 lines) for the pumpWidget invocation
		end := i + 45
		if end > len(lines) {
			end = len(lines)
		}
		chunk := strings.Join(lines[i:end], "\n")

		// If the test already includes the shell widget, contract is satisfied
		if strings.Contains(chunk, shell.shellName) {
			continue
		}

		// Check if a screen is pumped directly into MaterialApp
		dm := directScreenRe.FindStringSubmatch(chunk)
		if len(dm) > 1 {
			screenName := dm[1]
			key := fmt.Sprintf("%s:%d", block.file, lineNum)
			if seen[key] {
				continue
			}
			seen[key] = true

			effectiveWidth := w - shell.chromeWidth
			msg := fmt.Sprintf(
				"Desktop layout test configures %.0fx%.0f viewport but mounts %s directly in MaterialApp, omitting %s shell; desktop chrome (%.0f dp sidebar) is omitted from layout constraints",
				w, h, screenName, shell.shellName, shell.chromeWidth,
			)
			remediation := fmt.Sprintf(
				"Mount %s inside %s, or adjust test viewport to reflect true content-area bounds (%.0f dp effective width instead of %.0f dp).",
				screenName, shell.shellName, effectiveWidth, w,
			)

			finding := Finding{
				Rule:        "test-viewport-chrome-contract",
				Severity:    "low",
				Category:    "quality",
				File:        block.file,
				Line:        lineNum,
				Message:     msg,
				Remediation: remediation,
				Confidence:  "High",
				Explanation: &model.FindingExplanation{
					RuleRationale:   "UI layout tests for responsive screens must account for application chrome to test true content constraints.",
					EvidenceSummary: fmt.Sprintf("Simulated viewport %.0f dp omits %.0f dp shell chrome (effective content width %.0f dp).", w, shell.chromeWidth, effectiveWidth),
					EvidenceKind:    "contract-trace",
					EvidenceSteps: []model.ExplainedStep{
						{
							StepNumber: 1,
							Kind:       "source",
							Location:   fmt.Sprintf("%s:%d", block.file, lineNum),
							Statement:  fmt.Sprintf("Test configures desktop viewport physicalSize = Size(%.0f, %.0f)", w, h),
						},
						{
							StepNumber: 2,
							Kind:       "state",
							Statement:  fmt.Sprintf("Screen %s mounted directly in MaterialApp without shell %s", screenName, shell.shellName),
						},
						{
							StepNumber: 3,
							Kind:       "sink",
							Statement:  fmt.Sprintf("Layout tested against unconstrained %.0f dp width rather than actual %.0f dp content width", w, effectiveWidth),
						},
					},
				},
			}
			findings = append(findings, finding)
		}
	}

	return findings
}
