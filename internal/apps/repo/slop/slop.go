package slop

import "github.com/jakej985-rgb/m3tal-review/protocol"

// Rules returns all Repo slop detector metadata.
func Rules() []protocol.RuleInfo {
	return nil
}

// Analyze runs Repo slop detectors.
func Analyze(filePath string, lines []string, allowed func(int) bool) []protocol.Finding {
	return nil
}
