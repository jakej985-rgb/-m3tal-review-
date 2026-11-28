package buildsystem

import (
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/repository/scanner"
)

func TestDetectBuildSystemsDotNetAndEmpty(t *testing.T) {
	empty := Detect(scanner.RepositoryInventory{})
	if len(empty) != 0 {
		t.Fatalf("expected 0 build systems on empty inventory, got %+v", empty)
	}

	inv := scanner.RepositoryInventory{
		Manifests: map[string][]string{
			"a.sln":          {"a.sln"},
			"App.csproj":     {"src/App.csproj"},
			"go.mod":         {"go.mod"},
			"unrelated.conf": {"unrelated.conf"},
		},
	}
	got := Detect(inv)
	if len(got) != 3 {
		t.Fatalf("expected 3 build systems (Go Modules + 2 NuGet/MSBuild), got %+v", got)
	}
}
