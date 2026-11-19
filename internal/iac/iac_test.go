package iac

import (
	"strings"
	"testing"
)

func collectRuleIDs(findings []ConfigFinding) map[string]bool {
	m := make(map[string]bool, len(findings))
	for _, f := range findings {
		m[f.RuleID] = true
	}
	return m
}

func TestAnalyzeDockerfile(t *testing.T) {
	insecureDoc := `FROM alpine:latest
ADD https://example.com/payload.tar.gz /app/
EXPOSE 22
ENV DB_PASSWORD=supersecret
CMD ["/app/run"]`

	findings := AnalyzeDockerfile("Dockerfile", insecureDoc)
	if len(findings) == 0 {
		t.Fatalf("expected findings for insecure Dockerfile")
	}

	ruleMap := collectRuleIDs(findings)
	if !ruleMap["docker-unpinned-base-image"] {
		t.Errorf("missing docker-unpinned-base-image")
	}
	if !ruleMap["docker-insecure-add"] {
		t.Errorf("missing docker-insecure-add")
	}
	if !ruleMap["docker-exposed-ssh"] {
		t.Errorf("missing docker-exposed-ssh")
	}
	if !ruleMap["docker-hardcoded-secret"] {
		t.Errorf("missing docker-hardcoded-secret")
	}
	if !ruleMap["docker-missing-user"] {
		t.Errorf("missing docker-missing-user")
	}

	secureDoc := `FROM alpine@sha256:7144f7e169a30bb814fb81f874326d7d3d0b320e743b8630363471e03296580b
COPY run.sh /app/
USER appuser
CMD ["/app/run.sh"]`

	secureFindings := AnalyzeDockerfile("Dockerfile.prod", secureDoc)
	if len(secureFindings) != 0 {
		t.Errorf("expected 0 findings for secure Dockerfile, got %d", len(secureFindings))
	}
}

func TestAnalyzeWorkflow(t *testing.T) {
	insecureWorkflow := `name: CI
on: pull_request_target
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo ${{ secrets.DEPLOY_TOKEN }}`

	findings := AnalyzeWorkflow(".github/workflows/ci.yml", insecureWorkflow)
	if len(findings) == 0 {
		t.Fatalf("expected findings for insecure workflow")
	}

	rules := collectRuleIDs(findings)
	if !rules["workflow-unsafe-pr-target"] {
		t.Errorf("missing workflow-unsafe-pr-target")
	}
	if !rules["workflow-excessive-permissions"] {
		t.Errorf("missing workflow-excessive-permissions")
	}
	if !rules["workflow-secret-echo"] {
		t.Errorf("missing workflow-secret-echo")
	}
}

func TestAnalyzeKubernetes(t *testing.T) {
	insecureK8s := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  template:
    spec:
      hostPID: true
      containers:
        - name: app
          image: app:v1
          securityContext:
            privileged: true
            runAsUser: 0`

	findings := AnalyzeKubernetes("deploy/k8s.yaml", insecureK8s)
	if len(findings) == 0 {
		t.Fatalf("expected findings for insecure k8s manifest")
	}

	rules := collectRuleIDs(findings)
	if !rules["k8s-privileged-container"] {
		t.Errorf("missing k8s-privileged-container")
	}
	if !rules["k8s-host-namespace"] {
		t.Errorf("missing k8s-host-namespace")
	}
	if !rules["k8s-root-container"] {
		t.Errorf("missing k8s-root-container")
	}
	if !rules["k8s-missing-resource-limits"] {
		t.Errorf("missing k8s-missing-resource-limits")
	}
}

func TestAnalyzeTerraform(t *testing.T) {
	insecureTF := `resource "aws_security_group" "allow_ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "data_bucket" {
  bucket = "my-bucket"
}

resource "aws_iam_policy" "wildcard" {
  policy = jsonencode({
    Statement = [{
      Action   = "*"
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}`

	findings := AnalyzeTerraform("infra/main.tf", insecureTF)
	if len(findings) == 0 {
		t.Fatalf("expected findings for insecure Terraform")
	}

	rules := collectRuleIDs(findings)
	if !rules["iac-open-ingress"] {
		t.Errorf("missing iac-open-ingress")
	}
	if !rules["iac-unencrypted-storage"] {
		t.Errorf("missing iac-unencrypted-storage")
	}
	if !rules["iac-wildcard-iam"] {
		t.Errorf("missing iac-wildcard-iam")
	}
}

func TestCoReview(t *testing.T) {
	dockerfile := `FROM alpine:3.19
EXPOSE 8080 9090`

	k8sManifest := `apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  containers:
    - name: c1
      ports:
        - containerPort: 8080`

	corrs := CorrelateContainerPorts("Dockerfile", dockerfile, "pod.yaml", k8sManifest)
	if len(corrs) != 1 || !strings.Contains(corrs[0].Message, "9090") {
		t.Errorf("expected correlation for unmapped port 9090, got %+v", corrs)
	}

	apiRoutes := `routes:
  - path: /public/health
  - path: /admin/users/delete
  - path: /admin/config
    security:
      - BearerAuth: []`

	findings := AnalyzeAPIRoutes("routes.yaml", apiRoutes)
	if len(findings) != 1 || findings[0].RuleID != "coreview-unauthenticated-endpoint" {
		t.Errorf("expected unauthenticated endpoint finding for /admin/users/delete, got %+v", findings)
	}
}
