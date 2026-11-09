package language

import (
	"testing"
)

func TestCodeCheckerDetectsSupportedLanguages(t *testing.T) {
	checker := CodeChecker{}
	cases := map[string]CodeLanguage{
		"main.go":           LanguageGo,
		"app.jsx":           LanguageJavaScript,
		"app.tsx":           LanguageTypeScript,
		"script.py":         LanguagePython,
		"Main.java":         LanguageJava,
		"Main.kt":           LanguageKotlin,
		"main.c":            LanguageC,
		"main.cpp":          LanguageCpp,
		"main.cxx":          LanguageCpp,
		"main.c++":          LanguageCpp,
		"main.C":            LanguageCpp,
		"main.H":            LanguageCpp,
		"main.hh":           LanguageCpp,
		"main.hxx":          LanguageCpp,
		"Main.cs":           LanguageCSharp,
		"main.rs":           LanguageRust,
		"main.swift":        LanguageSwift,
		"index.php":         LanguagePHP,
		"README.md":         LanguageUnknown,
		"UPPERCASE.JS":      LanguageJavaScript,
		"Component.TSX":     LanguageTypeScript,
		"package-lock.json": LanguageUnknown,
	}
	for file, want := range cases {
		if got := checker.Language(file); got != want {
			t.Errorf("Language(%q) = %q, want %q", file, got, want)
		}
	}
}

func TestLanguageDetectionConfidenceAndReasons(t *testing.T) {
	checker := CodeChecker{}

	// High confidence by unambiguous extension
	res := checker.Detect("service.go", nil)
	if res.Language != LanguageGo || res.Confidence != ConfidenceHigh || res.Reason != "extension: .go" {
		t.Errorf("unexpected result for service.go: %+v", res)
	}

	res = checker.Detect("script.py", nil)
	if res.Language != LanguagePython || res.Confidence != ConfidenceHigh || res.Reason != "extension: .py" {
		t.Errorf("unexpected result for script.py: %+v", res)
	}

	res = checker.Detect("lib.rs", nil)
	if res.Language != LanguageRust || res.Confidence != ConfidenceHigh || res.Reason != "extension: .rs" {
		t.Errorf("unexpected result for lib.rs: %+v", res)
	}

	// Ambiguous extension without content gives Low confidence
	res = checker.Detect("types.h", nil)
	if res.Language != LanguageCpp || res.Confidence != ConfidenceLow || res.Reason != "ambiguous extension: .h" {
		t.Errorf("unexpected result for ambiguous types.h: %+v", res)
	}

	// Unknown extension
	res = checker.Detect("data.bin", nil)
	if res.Language != LanguageUnknown || res.Confidence != ConfidenceLow || res.Reason != "unknown extension" {
		t.Errorf("unexpected result for data.bin: %+v", res)
	}
}

func TestLanguageDetectionAmbiguousHeader(t *testing.T) {
	checker := CodeChecker{}

	// .h with C++ constructs
	cppHeader := []byte(`
#pragma once
#include <iostream>

namespace api {
class Service {
public:
    void execute();
};
}
`)
	res := checker.Detect("api/service.h", cppHeader)
	if res.Language != LanguageCpp || res.Confidence != ConfidenceHigh {
		t.Errorf("expected C++ for C++ header, got %+v", res)
	}

	// .h with pure C constructs
	cHeader := []byte(`
#ifndef LIB_H
#define LIB_H
#include <stdio.h>

typedef struct {
    int id;
} record_t;

extern int process_record(record_t *rec);
#endif
`)
	res = checker.Detect("include/lib.h", cHeader)
	if res.Language != LanguageC || res.Confidence != ConfidenceMedium {
		t.Errorf("expected C for C header, got %+v", res)
	}
}

func TestLanguageDetectionAmbiguousTSAndInc(t *testing.T) {
	checker := CodeChecker{}

	// .ts file that is actually XML translation file
	xmlTS := []byte(`<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE TS>
<TS version="2.1" language="de_DE">
</TS>
`)
	res := checker.Detect("translations/de.ts", xmlTS)
	if res.Language != LanguageUnknown || res.Confidence != ConfidenceHigh {
		t.Errorf("expected LanguageUnknown for XML .ts file, got %+v", res)
	}

	// .ts file that is normal TypeScript
	codeTS := []byte(`export interface User { id: string; }`)
	res = checker.Detect("models/user.ts", codeTS)
	if res.Language != LanguageTypeScript || res.Confidence != ConfidenceHigh {
		t.Errorf("expected TypeScript for TypeScript code, got %+v", res)
	}

	// .inc with PHP tag
	phpInc := []byte(`<?php
echo "included";
`)
	res = checker.Detect("config.inc", phpInc)
	if res.Language != LanguagePHP || res.Confidence != ConfidenceHigh {
		t.Errorf("expected PHP for .inc with <?php, got %+v", res)
	}
}

func TestLanguageDetectionShebang(t *testing.T) {
	checker := CodeChecker{}

	cases := []struct {
		file     string
		content  string
		expected CodeLanguage
		conf     Confidence
	}{
		{"bin/deploy", "#!/bin/bash\necho deploying", LanguageShell, ConfidenceHigh},
		{"scripts/tool", "#!/usr/bin/env python3\nimport sys", LanguagePython, ConfidenceHigh},
		{"build/server", "#!/usr/bin/env node\nconsole.log(1)", LanguageJavaScript, ConfidenceHigh},
		{"cron/job", "#!/usr/bin/php\n<?php phpinfo();", LanguagePHP, ConfidenceHigh},
	}

	for _, c := range cases {
		res := checker.Detect(c.file, []byte(c.content))
		if res.Language != c.expected || res.Confidence != c.conf {
			t.Errorf("Detect(%q) = %+v, want Lang=%s Conf=%s", c.file, res, c.expected, c.conf)
		}
	}
}

func TestLanguageDetectionContentSniffingWithoutExtension(t *testing.T) {
	checker := CodeChecker{}

	// Go package declaration in extensionless file
	goContent := []byte(`package main

func main() {}
`)
	res := checker.Detect("internal/cmd/entrypoint", goContent)
	if res.Language != LanguageGo || res.Confidence != ConfidenceHigh {
		t.Errorf("expected Go from content sniffing, got %+v", res)
	}

	// PHP opening tag in extensionless file
	phpContent := []byte(`<?php
header("Location: /");
`)
	res = checker.Detect("web/redirector", phpContent)
	if res.Language != LanguagePHP || res.Confidence != ConfidenceHigh {
		t.Errorf("expected PHP from content sniffing, got %+v", res)
	}

	// Python constructs in extensionless file
	pyContent := []byte(`import os
def run():
    print(os.getcwd())
`)
	res = checker.Detect("bin/task", pyContent)
	if res.Language != LanguagePython || res.Confidence != ConfidenceMedium {
		t.Errorf("expected Python from content sniffing, got %+v", res)
	}
}

func TestLanguageOverrides(t *testing.T) {
	overrides := map[string]string{
		"scripts/run":        "shell",
		"*.custom":           "python",
		"internal/**/*.stub": "go",
		"legacy.h":           "c",
	}

	checker := NewChecker(overrides)

	// Exact path override
	res := checker.Detect("scripts/run", []byte("plain text"))
	if res.Language != LanguageShell || res.Confidence != ConfidenceHigh || res.Reason != "override: scripts/run" {
		t.Errorf("expected shell override for scripts/run, got %+v", res)
	}

	// Glob override (*.custom)
	res = checker.Detect("models/data.custom", []byte("any content"))
	if res.Language != LanguagePython || res.Confidence != ConfidenceHigh || res.Reason != "override: *.custom" {
		t.Errorf("expected python override for data.custom, got %+v", res)
	}

	// Recursive glob override (internal/**/*.stub)
	res = checker.Detect("internal/auth/handler.stub", []byte("package stub"))
	if res.Language != LanguageGo || res.Confidence != ConfidenceHigh {
		t.Errorf("expected go override for handler.stub, got %+v", res)
	}

	// Basename override
	res = checker.Detect("src/legacy.h", nil)
	if res.Language != LanguageC || res.Confidence != ConfidenceHigh || res.Reason != "override: legacy.h" {
		t.Errorf("expected C override for legacy.h, got %+v", res)
	}
}

func TestGlobalDefaultOverrides(t *testing.T) {
	defer SetDefaultOverrides(nil)

	SetDefaultOverrides(map[string]string{
		"*.rule": "rust",
	})

	// Unconfigured CodeChecker{} picks up global overrides
	checker := CodeChecker{}
	res := checker.Detect("rules/main.rule", nil)
	if res.Language != LanguageRust || res.Confidence != ConfidenceHigh {
		t.Errorf("expected global override to detect rust, got %+v", res)
	}
}
