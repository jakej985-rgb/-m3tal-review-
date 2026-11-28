package infrastructure

import (
	"context"
	"path"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analyzers"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/repo"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/shell"
	"github.com/jakej985-rgb/m3tal-review/internal/planning"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
	"github.com/jakej985-rgb/m3tal-review/protocol"
)

var (
	reDockerLatest = regexp.MustCompile(`(?i)^\s*FROM\s+\S+:latest\b`)
	reDockerAddURL = regexp.MustCompile(`(?i)^\s*ADD\s+https?://`)
)

// DockerAnalyzer checks Dockerfile security and pinning.
type DockerAnalyzer struct{}

func (DockerAnalyzer) Metadata() planning.AnalyzerMetadata {
	return planning.AnalyzerMetadata{
		ID: "infra-docker", Name: "Docker analysis", Kind: planning.KindInfrastructure,
		Frameworks: []string{"Docker"}, Capabilities: []string{"infrastructure"},
		Description: "Dockerfile and Compose security checks",
	}
}

func (DockerAnalyzer) Analyze(_ context.Context, req analyzers.Request) (analyzers.Result, error) {
	var findings []review.Finding
	for _, f := range req.Files {
		base := path.Base(f.Path)
		if base != "Dockerfile" && !strings.HasPrefix(base, "Dockerfile.") {
			continue
		}
		for idx, raw := range strings.Split(f.Content, "\n") {
			trimmed := strings.TrimSpace(raw)
			if reDockerLatest.MatchString(raw) {
				findings = append(findings, review.Finding{
					Rule: "docker/bug/unpinned-base-image", Category: "bug", Severity: "medium", Confidence: "high",
					File: f.Path, Line: idx + 1, Message: "Dockerfile uses mutable :latest base image tag",
					Snippet: trimmed, Remediation: "Pin the base image to an explicit version or digest.",
				})
			}
			if reDockerAddURL.MatchString(raw) {
				findings = append(findings, review.Finding{
					Rule: "docker/security/remote-add", Category: "security", Severity: "medium", Confidence: "high",
					File: f.Path, Line: idx + 1, Message: "ADD with remote URL fetches unverified artifacts",
					Snippet: trimmed, Remediation: "Use curl/wget with checksum verification and COPY.",
				})
			}
		}
	}
	return analyzers.Result{AnalyzerID: "infra-docker", Findings: findings}, nil
}

// GitHubActionsAnalyzer delegates workflow checks to internal/apps/shell.
type GitHubActionsAnalyzer struct{}

func (GitHubActionsAnalyzer) Metadata() planning.AnalyzerMetadata {
	return planning.AnalyzerMetadata{
		ID: "infra-gha", Name: "GitHub Actions analysis", Kind: planning.KindInfrastructure,
		Frameworks: []string{"GitHub Actions"}, Capabilities: []string{"infrastructure"},
		Description: "Workflow pinning, permissions, and script injection checks",
	}
}

func (GitHubActionsAnalyzer) Analyze(_ context.Context, req analyzers.Request) (analyzers.Result, error) {
	var pFiles []protocol.File
	for _, f := range req.Files {
		if strings.HasPrefix(f.Path, ".github/workflows/") {
			pFiles = append(pFiles, protocol.File{Path: f.Path, Status: "modified", Content: f.Content})
		}
	}
	out := (shell.App{}).Run(protocol.Input{Protocol: protocol.Version, Files: pFiles})
	return analyzers.Result{AnalyzerID: "infra-gha", Findings: toReviewFindings(out.Findings)}, nil
}

// TerraformAnalyzer delegates .tf/.tfvars checks to internal/apps/repo.
type TerraformAnalyzer struct{}

func (TerraformAnalyzer) Metadata() planning.AnalyzerMetadata {
	return planning.AnalyzerMetadata{
		ID: "infra-terraform", Name: "Terraform analysis", Kind: planning.KindInfrastructure,
		Frameworks: []string{"Terraform"}, Capabilities: []string{"infrastructure"},
		Description: "Terraform CIDR and IaC misconfiguration checks",
	}
}

func (TerraformAnalyzer) Analyze(_ context.Context, req analyzers.Request) (analyzers.Result, error) {
	var pFiles []protocol.File
	for _, f := range req.Files {
		if strings.HasSuffix(f.Path, ".tf") || strings.HasSuffix(f.Path, ".tfvars") {
			pFiles = append(pFiles, protocol.File{Path: f.Path, Status: "modified", Content: f.Content})
		}
	}
	out := (repo.App{}).Run(protocol.Input{Protocol: protocol.Version, Files: pFiles})
	return analyzers.Result{AnalyzerID: "infra-terraform", Findings: toReviewFindings(out.Findings)}, nil
}

func toReviewFindings(in []protocol.Finding) []review.Finding {
	out := make([]review.Finding, 0, len(in))
	for _, f := range in {
		out = append(out, review.Finding{
			Rule: f.Rule, Category: f.Category, Severity: f.Severity, Confidence: f.Confidence,
			File: f.File, Line: f.Line, Message: f.Message, Remediation: f.Remediation, Snippet: f.Evidence,
		})
	}
	return out
}

// RegisterAll registers all infrastructure analyzers.
func RegisterAll(reg *analyzers.Registry) {
	reg.Register(DockerAnalyzer{})
	reg.Register(GitHubActionsAnalyzer{})
	reg.Register(TerraformAnalyzer{})
}
