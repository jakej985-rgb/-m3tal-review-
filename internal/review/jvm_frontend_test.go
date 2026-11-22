package review

import (
	"testing"
)

func TestJVMCoroutineLeakRule_DetectsGlobalScope(t *testing.T) {
	src := `
package com.example.service

import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch

class UserService {
    fun fetchUserData(userId: String) {
        GlobalScope.launch {
            apiClient.getUser(userId)
        }
    }
}
`
	diff := goDiff("src/main/kotlin/com/example/UserService.kt", src)
	findings := (JVMCoroutineLeakRule{}).Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for GlobalScope.launch, got %d", len(findings))
	}
	if findings[0].Rule != "jvm-coroutine-leak" {
		t.Errorf("expected rule jvm-coroutine-leak, got %s", findings[0].Rule)
	}
}

func TestJVMInsecureDeserializationRule_DetectsUnfilteredReadObject(t *testing.T) {
	src := `
package com.example.security;

import java.io.InputStream;
import java.io.ObjectInputStream;

public class PayloadParser {
    public Object parse(InputStream input) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(input);
        return ois.readObject();
    }
}
`
	diff := goDiff("src/main/java/com/example/PayloadParser.java", src)
	findings := (JVMInsecureDeserializationRule{}).Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unfiltered readObject, got %d", len(findings))
	}
	if findings[0].Rule != "jvm-insecure-deserialization" {
		t.Errorf("expected rule jvm-insecure-deserialization, got %s", findings[0].Rule)
	}
	if findings[0].Severity != "critical" {
		t.Errorf("expected severity critical, got %s", findings[0].Severity)
	}
}

func TestJVMInsecureDeserializationRule_AllowsObjectInputFilter(t *testing.T) {
	src := `
package com.example.security;

import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectInputFilter;

public class PayloadParser {
    public Object parse(InputStream input) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(input);
        ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.example.model.*"));
        return ois.readObject();
    }
}
`
	diff := goDiff("src/main/java/com/example/PayloadParser.java", src)
	findings := (JVMInsecureDeserializationRule{}).Check(diff)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when ObjectInputFilter is used, got %d", len(findings))
	}
}
