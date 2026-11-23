package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// ImageCacheAspectRule detects Flutter Image widgets (Image.asset, Image.network,
// ResizeImage) that specify both cacheWidth and cacheHeight simultaneously.
// When both parameters are provided to the image cache decode pipe, Flutter forces
// decoding into that exact pixel bounding box without preserving native aspect ratio,
// leading to visible stretching or distortion of non-square images.
type ImageCacheAspectRule struct {
	ruleRuntime
}

func (ImageCacheAspectRule) Name() string {
	return "flutter-image-cache-distortion"
}

var (
	dartWidgetFileRe = regexp.MustCompile(`\.dart$`)

	// imageInvocationRe detects image constructors or ResizeImage
	imageInvocationRe = regexp.MustCompile(`(?:Image\.(?:asset|network|file|memory)|ResizeImage)\s*\(`)
)

func (r ImageCacheAspectRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r ImageCacheAspectRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !dartWidgetFileRe.MatchString(block.file) || isTestFile(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		if !imageInvocationRe.MatchString(scanText) {
			continue
		}

		matches := imageInvocationRe.FindAllStringIndex(scanText, -1)
		for _, m := range matches {
			// Extract invocation chunk (up to 300 chars or closing paren)
			chunkEnd := m[1] + 300
			if chunkEnd > len(scanText) {
				chunkEnd = len(scanText)
			}
			chunk := scanText[m[0]:chunkEnd]

			// Check if both cacheWidth and cacheHeight are present in this invocation
			hasCacheWidth := strings.Contains(chunk, "cacheWidth:")
			hasCacheHeight := strings.Contains(chunk, "cacheHeight:")

			if hasCacheWidth && hasCacheHeight {
				lineNum := startLine + strings.Count(scanText[:m[0]], "\n")
				if block.addedLines[lineNum] || r.workingTree || len(block.addedLines) > 0 {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:        "flutter-image-cache-distortion",
							Severity:    "medium",
							File:        block.file,
							Line:        lineNum,
							Message:     "Image decode specifies both cacheWidth and cacheHeight, forcing non-uniform aspect ratio decoding",
							Remediation: "Constrain only a single dimension (cacheWidth OR cacheHeight) or compute proportional dimensions to avoid image stretching.",
						})
					}
				}
			}
		}
	}

	return findings
}
