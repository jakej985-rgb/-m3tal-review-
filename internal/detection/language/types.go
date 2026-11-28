package language

// DetectionStatus classifies how a file was identified.
type DetectionStatus string

const (
	Detected  DetectionStatus = "detected"
	Ambiguous DetectionStatus = "ambiguous"
	Unknown   DetectionStatus = "unknown"
	Excluded  DetectionStatus = "excluded"
)

// FileDetection records the language classification and supporting evidence for a single file.
type FileDetection struct {
	Path               string          `json:"path"`
	Language           string          `json:"language,omitempty"`
	SecondaryLanguages []string        `json:"secondary_languages,omitempty"`
	Confidence         float64         `json:"confidence"`
	Status             DetectionStatus `json:"status"`
	IsManifest         bool            `json:"is_manifest,omitempty"`
	Evidence           []string        `json:"evidence,omitempty"`
}

// LanguageInfo summarizes a detected language across the repository.
type LanguageInfo struct {
	Name       string   `json:"name"`
	Tier       int      `json:"tier"`
	FileCount  int      `json:"file_count"`
	Confidence float64  `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

// RepositoryDetection is the full language detection result for a repository.
type RepositoryDetection struct {
	Languages []LanguageInfo  `json:"languages"`
	Files     []FileDetection `json:"files"`
	Unknown   []string        `json:"unknown,omitempty"`
	Ambiguous []string        `json:"ambiguous,omitempty"`
	Excluded  []string        `json:"excluded,omitempty"`
}

// DetectConfig holds explicit user overrides for language detection.
type DetectConfig struct {
	Overrides map[string]string // glob pattern or extension -> language name
}

// LanguageCapability honestly documents what m3tal-review supports for a language.
type LanguageCapability struct {
	Name       string   `json:"name"`
	Tier       int      `json:"tier"`
	Extensions []string `json:"extensions"`
	Detection  bool     `json:"detection"`
	Basic      bool     `json:"basic_analysis"`
	Static     bool     `json:"static_analysis"`
	AST        bool     `json:"ast_analysis"`
	Semantic   bool     `json:"semantic_analysis"`
	Flow       bool     `json:"flow_analysis"`
	Repair     bool     `json:"repair"`
}

// SupportedLanguages returns the canonical Tier 1 and Tier 2 language capability matrix.
func SupportedLanguages() []LanguageCapability {
	return []LanguageCapability{
		{Name: "Go", Tier: 1, Extensions: []string{".go"}, Detection: true, Basic: true, Static: true, AST: true, Semantic: true, Flow: true, Repair: true},
		{Name: "Python", Tier: 1, Extensions: []string{".py", ".pyi"}, Detection: true, Basic: true, Static: true, AST: true, Semantic: false, Flow: false, Repair: true},
		{Name: "JavaScript", Tier: 1, Extensions: []string{".js", ".mjs", ".cjs", ".jsx"}, Detection: true, Basic: true, Static: true, AST: true, Semantic: false, Flow: false, Repair: false},
		{Name: "TypeScript", Tier: 1, Extensions: []string{".ts", ".mts", ".cts", ".tsx"}, Detection: true, Basic: true, Static: true, AST: true, Semantic: false, Flow: false, Repair: false},
		{Name: "Dart", Tier: 1, Extensions: []string{".dart"}, Detection: true, Basic: true, Static: true, AST: false, Semantic: false, Flow: false, Repair: false},
		{Name: "Rust", Tier: 1, Extensions: []string{".rs"}, Detection: true, Basic: true, Static: true, AST: false, Semantic: false, Flow: false, Repair: false},
		{Name: "Java", Tier: 1, Extensions: []string{".java"}, Detection: true, Basic: true, Static: true, AST: false, Semantic: false, Flow: false, Repair: false},
		{Name: "C/C++", Tier: 1, Extensions: []string{".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hxx"}, Detection: true, Basic: true, Static: true, AST: false, Semantic: false, Flow: false, Repair: false},
		{Name: "C#", Tier: 2, Extensions: []string{".cs"}, Detection: true, Basic: true, Static: true, AST: false, Semantic: false, Flow: false, Repair: false},
		{Name: "Kotlin", Tier: 2, Extensions: []string{".kt", ".kts"}, Detection: true, Basic: true, Static: true, AST: false, Semantic: false, Flow: false, Repair: false},
		{Name: "Swift", Tier: 2, Extensions: []string{".swift"}, Detection: true, Basic: true, Static: true, AST: false, Semantic: false, Flow: false, Repair: false},
		{Name: "PHP", Tier: 2, Extensions: []string{".php"}, Detection: true, Basic: true, Static: true, AST: false, Semantic: false, Flow: false, Repair: false},
		{Name: "Ruby", Tier: 2, Extensions: []string{".rb"}, Detection: true, Basic: true, Static: false, AST: false, Semantic: false, Flow: false, Repair: false},
		{Name: "Shell", Tier: 2, Extensions: []string{".sh", ".bash", ".zsh"}, Detection: true, Basic: true, Static: true, AST: false, Semantic: false, Flow: false, Repair: false},
		{Name: "SQL", Tier: 2, Extensions: []string{".sql"}, Detection: true, Basic: true, Static: false, AST: false, Semantic: false, Flow: false, Repair: false},
		{Name: "YAML", Tier: 2, Extensions: []string{".yml", ".yaml"}, Detection: true, Basic: true, Static: true, AST: false, Semantic: false, Flow: false, Repair: false},
		{Name: "Terraform", Tier: 2, Extensions: []string{".tf", ".tfvars"}, Detection: true, Basic: true, Static: true, AST: false, Semantic: false, Flow: false, Repair: false},
	}
}
