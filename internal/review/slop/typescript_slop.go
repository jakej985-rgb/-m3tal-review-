package slop

// checkTypeScriptSyntax uses the shared JavaScript-compatible syntax scanner
// for TypeScript and TSX control-flow structures.
func (r SlopRule) checkTypeScriptSyntax(file string, added []int) []Finding {
	source, err := r.readSourceForAnalysis(file)
	if err != nil {
		return r.analysisReadError(file, err)
	}
	return analyzeBraceSlop(file, "TypeScript", string(source), addedLineMap(added))
}

func (r SlopRule) checkTypeScriptRegex(fd FileDiff) []Finding {
	return r.checkAddedLineRegex(fd)
}
