package apps

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
)

//go:embed registry.json
var embeddedRegistry []byte

// RegistryEntry describes an expected language app in registry.json.
type RegistryEntry struct {
	Name       string   `json:"name"`
	Extensions []string `json:"extensions"`
	Optional   bool     `json:"optional"`
}

// Registry is the embedded install manifest of expected apps.
type Registry struct {
	Apps []RegistryEntry `json:"apps"`
}

// LoadRegistry parses the embedded registry.json.
func LoadRegistry() (Registry, error) {
	var reg Registry
	if err := json.Unmarshal(embeddedRegistry, &reg); err != nil {
		return Registry{}, fmt.Errorf("parse embedded registry: %w", err)
	}
	return reg, nil
}

// Manifest is the optional static review-app.json shipped alongside an app.
type Manifest struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Protocol    string   `json:"protocol"`
	Extensions  []string `json:"extensions"`
	Inputs      []string `json:"inputs"`
	Description string   `json:"description,omitempty"`
	Executable  string   `json:"executable,omitempty"`
	Rules       []string `json:"rules,omitempty"`
}

// LoadManifest reads and parses a review-app.json file.
func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest %s: %w", path, err)
	}
	return m, nil
}
