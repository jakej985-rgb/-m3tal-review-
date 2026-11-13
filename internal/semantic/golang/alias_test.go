package golang

import (
	"context"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

var aliasFiles = map[string]string{
	"go.mod": "module example.com/alias\n\ngo 1.23\n",
	"main.go": `package main

import "example.com/alias/lib"

// LocalID is a package-qualified alias chain across packages.
type LocalID = lib.UserID

func main() {
	var u lib.UserID = "u7"
	println(string(u))
	var l LocalID
	_ = l
}
`,
	"lib/lib.go": `package lib

type UserID = string

type SessionID string

type AliasChain = UserID

type DeepChain = AliasChain

func Lookup(id UserID) SessionID { return SessionID(id) }
`,
}

func loadAliasFixture(t *testing.T) *semantic.Program {
	t.Helper()
	dir := writeModule(t, aliasFiles)
	prog, err := Load(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return prog
}

func typeByName(t *testing.T, pkg *semantic.Package, name string) *semantic.Type {
	t.Helper()
	for _, typ := range pkg.Types {
		if typ.Name == name {
			return typ
		}
	}
	t.Fatalf("type %q not modeled in package %s", name, pkg.Path)
	return nil
}

func TestTypeAliasIdentity(t *testing.T) {
	prog := loadAliasFixture(t)
	lib := findPackage(t, prog, "example.com/alias/lib")

	userID := typeByName(t, lib, "UserID")
	if userID.Kind != semantic.TypeAlias {
		t.Fatalf("UserID kind = %v, want TypeAlias", userID.Kind)
	}
	if !userID.IsAlias {
		t.Fatal("UserID.IsAlias = false, want true")
	}
	if userID.Package != "example.com/alias/lib" {
		t.Fatalf("UserID.Package = %q", userID.Package)
	}
	if userID.Aliasee == nil {
		t.Fatal("UserID.Aliasee is nil")
	}
	if userID.Aliasee.Kind != semantic.TypeBasic || userID.Aliasee.Name != "string" {
		t.Fatalf("UserID.Aliasee = %+v, want basic string", userID.Aliasee)
	}
	// The alias must be a distinct cache entry from its target.
	if userID.Aliasee.Kind == semantic.TypeAlias {
		t.Fatal("UserID.Aliasee should not itself be an alias")
	}
}

func TestDefinedTypeDistinctFromAlias(t *testing.T) {
	prog := loadAliasFixture(t)
	lib := findPackage(t, prog, "example.com/alias/lib")

	userID := typeByName(t, lib, "UserID")
	sessionID := typeByName(t, lib, "SessionID")

	if sessionID.Kind != semantic.TypeNamed {
		t.Fatalf("SessionID kind = %v, want TypeNamed", sessionID.Kind)
	}
	if sessionID.IsAlias {
		t.Fatal("SessionID.IsAlias = true for a defined type")
	}
	if userID == sessionID {
		t.Fatal("alias and defined type share a model object")
	}
	if userID.Text == sessionID.Text {
		t.Fatalf("alias and defined type have identical text %q", userID.Text)
	}
}

func TestAliasChainPreservesLinks(t *testing.T) {
	prog := loadAliasFixture(t)
	lib := findPackage(t, prog, "example.com/alias/lib")

	aliasChain := typeByName(t, lib, "AliasChain")
	if aliasChain.Kind != semantic.TypeAlias || !aliasChain.IsAlias {
		t.Fatalf("AliasChain = %+v, want TypeAlias", aliasChain)
	}
	// Immediate RHS is the UserID alias, not the fully-expanded string.
	if aliasChain.Aliasee == nil || aliasChain.Aliasee.Kind != semantic.TypeAlias {
		t.Fatalf("AliasChain.Aliasee = %+v, want TypeAlias UserID", aliasChain.Aliasee)
	}
	if aliasChain.Aliasee.Name != "UserID" {
		t.Fatalf("AliasChain.Aliasee.Name = %q, want UserID", aliasChain.Aliasee.Name)
	}
	deep := typeByName(t, lib, "DeepChain")
	if deep.Aliasee == nil || deep.Aliasee.Name != "AliasChain" {
		t.Fatalf("DeepChain.Aliasee = %+v, want AliasChain", deep.Aliasee)
	}
}

func TestAliasInSignature(t *testing.T) {
	prog := loadAliasFixture(t)

	lookup := findFunction(t, prog, "example.com/alias/lib.Lookup")
	if lookup.Signature == nil || len(lookup.Signature.Params) != 1 {
		t.Fatalf("Lookup signature = %+v", lookup.Signature)
	}
	param := lookup.Signature.Params[0]
	if param.Kind != semantic.TypeAlias || param.Name != "UserID" {
		t.Fatalf("Lookup param = %+v, want alias UserID", param)
	}
	if param.Aliasee == nil || param.Aliasee.Kind != semantic.TypeBasic {
		t.Fatalf("Lookup param Aliasee = %+v", param.Aliasee)
	}
	if len(lookup.Signature.Results) != 1 || lookup.Signature.Results[0].Kind != semantic.TypeNamed {
		t.Fatalf("Lookup results = %+v", lookup.Signature.Results)
	}
}

func TestAliasUsedAsValueType(t *testing.T) {
	prog := loadAliasFixture(t)

	// A variable declared with the alias type keeps the alias identity.
	mainFn := findFunction(t, prog, "example.com/alias.main")
	var sawAlias bool
	for _, v := range mainFn.Values {
		if v.Type != nil && v.Type.Kind == semantic.TypeAlias && v.Type.Name == "UserID" {
			sawAlias = true
		}
	}
	if !sawAlias {
		t.Fatal("no modeled value carries alias type UserID in main")
	}
}

func TestCrossPackageAlias(t *testing.T) {
	prog := loadAliasFixture(t)
	main := findPackage(t, prog, "example.com/alias")

	localID := typeByName(t, main, "LocalID")
	if localID.Kind != semantic.TypeAlias || !localID.IsAlias {
		t.Fatalf("LocalID = %+v, want TypeAlias", localID)
	}
	if localID.Package != "example.com/alias" {
		t.Fatalf("LocalID.Package = %q", localID.Package)
	}
	// The immediate RHS is the lib.UserID alias: deterministic,
	// package-qualified identity.
	if localID.Aliasee == nil || localID.Aliasee.Kind != semantic.TypeAlias {
		t.Fatalf("LocalID.Aliasee = %+v, want alias", localID.Aliasee)
	}
	if localID.Aliasee.Name != "UserID" || localID.Aliasee.Package != "example.com/alias/lib" {
		t.Fatalf("LocalID.Aliasee = %+v, want lib.UserID", localID.Aliasee)
	}
	if localID.Aliasee.Aliasee == nil || localID.Aliasee.Aliasee.Name != "string" {
		t.Fatalf("LocalID.Aliasee.Aliasee = %+v, want string", localID.Aliasee.Aliasee)
	}
}
