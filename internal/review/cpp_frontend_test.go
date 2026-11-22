package review

import (
	"testing"
)

func TestCPPUnboundedBufferRule_DetectsStrcpyAndSprintf(t *testing.T) {
	src := `
#include <stdio.h>
#include <string.h>

void format_user(const char* name) {
    char buf[64];
    strcpy(buf, name);
    char out[128];
    sprintf(out, "User: %s", buf);
}
`
	diff := goDiff("src/user.c", src)
	findings := (CPPUnboundedBufferRule{}).Check(diff)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for strcpy and sprintf, got %d", len(findings))
	}
	if findings[0].Rule != "cpp-unbounded-buffer" || findings[1].Rule != "cpp-unbounded-buffer" {
		t.Errorf("expected rule cpp-unbounded-buffer, got %s and %s", findings[0].Rule, findings[1].Rule)
	}
}

func TestCPPUnboundedBufferRule_AllowsSafeAlternatives(t *testing.T) {
	src := `
#include <stdio.h>
#include <string.h>

void format_user(const char* name) {
    char buf[64];
    strncpy(buf, name, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char out[128];
    snprintf(out, sizeof(out), "User: %s", buf);
}
`
	diff := goDiff("src/user.c", src)
	findings := (CPPUnboundedBufferRule{}).Check(diff)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when strncpy and snprintf are used, got %d", len(findings))
	}
}
