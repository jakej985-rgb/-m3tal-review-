package analysis

import (
	"encoding/json"
	"testing"
)

func TestAllCapabilities(t *testing.T) {
	caps := AllCapabilities()
	if len(caps) != 6 {
		t.Fatalf("expected 6 capabilities, got %d", len(caps))
	}

	expectedOrder := []string{
		"authproto",
		"concurrency",
		"flow",
		"protocol",
		"statemachine",
		"typestate",
	}

	for i, exp := range expectedOrder {
		if caps[i].Name != exp {
			t.Errorf("at index %d, expected %s, got %s", i, exp, caps[i].Name)
		}
		if len(caps[i].Languages) == 0 {
			t.Errorf("capability %s has empty Languages", caps[i].Name)
		}
		if len(caps[i].EpistemicStatuses) == 0 {
			t.Errorf("capability %s has empty EpistemicStatuses", caps[i].Name)
		}
	}
}

func TestLookupCapability(t *testing.T) {
	cap, ok := LookupCapability("concurrency")
	if !ok {
		t.Fatalf("expected to find concurrency capability")
	}
	if cap.Name != "concurrency" || cap.Version != "1.0.0" {
		t.Errorf("unexpected capability: %+v", cap)
	}

	_, ok = LookupCapability("nonexistent")
	if ok {
		t.Errorf("expected nonexistent capability to return false")
	}
}

func TestCapabilitiesJSONSerialization(t *testing.T) {
	caps := AllCapabilities()
	data, err := json.Marshal(caps)
	if err != nil {
		t.Fatalf("failed to marshal capabilities: %v", err)
	}

	var roundtrip []AnalyzerCapability
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatalf("failed to unmarshal capabilities: %v", err)
	}
	if len(roundtrip) != len(caps) {
		t.Fatalf("roundtrip length mismatch: got %d, want %d", len(roundtrip), len(caps))
	}
}
