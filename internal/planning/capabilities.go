package planning

// AnalyzerKind classifies an analyzer's role in the system.
type AnalyzerKind string

const (
	KindLanguage       AnalyzerKind = "language"
	KindFramework      AnalyzerKind = "framework"
	KindInfrastructure AnalyzerKind = "infrastructure"
	KindCrossLanguage  AnalyzerKind = "crosslanguage"
	KindQuality        AnalyzerKind = "quality"
	KindSemantic       AnalyzerKind = "semantic"
)

// AnalyzerMetadata describes a registered analyzer and its applicability.
type AnalyzerMetadata struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Kind         AnalyzerKind `json:"kind"`
	Languages    []string     `json:"languages,omitempty"`
	Frameworks   []string     `json:"frameworks,omitempty"`
	Profiles     []string     `json:"profiles,omitempty"`
	Capabilities []string     `json:"capabilities,omitempty"`
	Description  string       `json:"description"`
}

// DefaultAnalyzers returns the built-in analyzer catalog.
func DefaultAnalyzers() []AnalyzerMetadata {
	return []AnalyzerMetadata{
		{ID: "lang-go", Name: "Go language analysis", Kind: KindLanguage, Languages: []string{"Go"}, Capabilities: []string{"ast", "static", "semantic", "repair"}, Description: "Go AST, correctness, security, and slop analysis"},
		{ID: "lang-python", Name: "Python language analysis", Kind: KindLanguage, Languages: []string{"Python"}, Capabilities: []string{"ast", "static", "repair"}, Description: "Python AST, security, and slop analysis"},
		{ID: "lang-js", Name: "JavaScript language analysis", Kind: KindLanguage, Languages: []string{"JavaScript"}, Capabilities: []string{"ast", "static"}, Description: "JavaScript security, bug, and slop analysis"},
		{ID: "lang-ts", Name: "TypeScript language analysis", Kind: KindLanguage, Languages: []string{"TypeScript"}, Capabilities: []string{"ast", "static"}, Description: "TypeScript security, bug, and slop analysis"},
		{ID: "lang-dart", Name: "Dart language analysis", Kind: KindLanguage, Languages: []string{"Dart"}, Capabilities: []string{"static"}, Description: "Dart static and pattern analysis"},
		{ID: "lang-rust", Name: "Rust language analysis", Kind: KindLanguage, Languages: []string{"Rust"}, Capabilities: []string{"static"}, Description: "Rust safety, FFI, and async lock analysis"},
		{ID: "lang-java", Name: "Java language analysis", Kind: KindLanguage, Languages: []string{"Java"}, Capabilities: []string{"static"}, Description: "Java security and concurrency analysis"},
		{ID: "lang-cpp", Name: "C/C++ language analysis", Kind: KindLanguage, Languages: []string{"C", "C++"}, Capabilities: []string{"static"}, Description: "C/C++ buffer, exec, and header analysis"},
		{ID: "fw-flutter", Name: "Flutter analysis", Kind: KindFramework, Frameworks: []string{"Flutter"}, Languages: []string{"Dart"}, Capabilities: []string{"framework"}, Description: "Flutter widget, accessibility, and lifecycle rules"},
		{ID: "fw-react", Name: "React analysis", Kind: KindFramework, Frameworks: []string{"React"}, Languages: []string{"JavaScript", "TypeScript"}, Capabilities: []string{"framework"}, Description: "React hook and XSS sink rules"},
		{ID: "fw-android", Name: "Android analysis", Kind: KindFramework, Frameworks: []string{"Android"}, Languages: []string{"Java", "Kotlin"}, Capabilities: []string{"framework"}, Description: "Android manifest and signing rules"},
		{ID: "infra-docker", Name: "Docker analysis", Kind: KindInfrastructure, Frameworks: []string{"Docker"}, Capabilities: []string{"infrastructure"}, Description: "Dockerfile and Compose security checks"},
		{ID: "infra-gha", Name: "GitHub Actions analysis", Kind: KindInfrastructure, Frameworks: []string{"GitHub Actions"}, Capabilities: []string{"infrastructure"}, Description: "Workflow pinning, permissions, and script injection checks"},
		{ID: "infra-terraform", Name: "Terraform analysis", Kind: KindInfrastructure, Frameworks: []string{"Terraform"}, Capabilities: []string{"infrastructure"}, Description: "Terraform CIDR and IaC misconfiguration checks"},
		{ID: "cross-security", Name: "Cross-language security", Kind: KindCrossLanguage, Profiles: []string{"fast", "security", "full"}, Capabilities: []string{"secrets", "injection"}, Description: "Secrets, credentials, and cross-language security patterns"},
		{ID: "cross-deps", Name: "Dependency analysis", Kind: KindCrossLanguage, Profiles: []string{"full", "security"}, Capabilities: []string{"dependencies"}, Description: "Manifest pinning, licenses, and vulnerability checks"},
		{ID: "semantic-go", Name: "Go semantic analysis", Kind: KindSemantic, Languages: []string{"Go"}, Profiles: []string{"full", "security"}, Capabilities: []string{"flow", "concurrency", "typestate"}, Description: "Whole-program Go SSA flow, concurrency, and typestate engines"},
	}
}
