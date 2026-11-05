package review

import (
	"strings"
	"testing"
)

func benchmarkDiff() string {
	var b strings.Builder
	for i := 0; i < 200; i++ {
		b.WriteString(extraDiff("pkg/f"+itoa(i)+".go",
			"package pkg\n\nimport \"fmt\"\n\nfunc F"+itoa(i)+"() {\n\tfmt.Println(\"x\")\n}\n"))
	}
	return b.String()
}

func BenchmarkParseDiffLarge(b *testing.B) {
	d := benchmarkDiff()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseDiff(d)
	}
}

func BenchmarkExtraRulesEngine(b *testing.B) {
	d := benchmarkDiff()
	engine := NewEngine(ExtraRules("/tmp/nonexistent-root")...)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Run(d)
	}
}

func BenchmarkMaskNonCode(b *testing.B) {
	src := "package main\n\n// comment with 'quotes' and \"strings\"\nfunc f() {\n\ts := \"literal\"\n\t_ = s\n}\n"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		maskNonCode("main.go", src)
	}
}
