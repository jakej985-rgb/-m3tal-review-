// Package iac correlates security configurations across heterogeneous artifacts.
package iac

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	routeAdminRe = regexp.MustCompile(`(?i)(?:/admin|/internal|/debug|/api/v\d+/(?:delete|update|users))`)
	routePathRe  = regexp.MustCompile(`(?i)^\s*(?:-\s*)?(?:path|pattern):\s*["']?([^"'\s]+)`)
)

func extractDockerfilePorts(content string) (ports []string) {
	for _, raw := range strings.Split(content, "\n") {
		if tr := strings.TrimSpace(raw); strings.HasPrefix(strings.ToUpper(tr), "EXPOSE ") {
			ports = append(ports, strings.Fields(tr[7:])...)
		}
	}
	return
}

func extractK8sContainerPorts(content string) []string {
	var result []string
	lines := strings.Split(content, "\n")
	for i := 0; i < len(lines); i++ {
		clean := strings.TrimPrefix(strings.TrimSpace(lines[i]), "- ")
		if strings.HasPrefix(clean, "containerPort:") {
			if parts := strings.Fields(clean); len(parts) >= 2 {
				result = append(result, parts[1])
			}
		}
	}
	return result
}

// CorrelateContainerPorts verifies that exposed container ports match orchestration specs.
func CorrelateContainerPorts(
	dockerfilePath, dockerContent string,
	k8sFilePath, k8sContent string,
) []CoReviewCorrelation {
	var corrs []CoReviewCorrelation
	dPorts := extractDockerfilePorts(dockerContent)
	kPorts := extractK8sContainerPorts(k8sContent)

	if len(dPorts) == 0 || len(kPorts) == 0 {
		return nil
	}

	kPortMap := make(map[string]bool)
	for _, p := range kPorts {
		kPortMap[p] = true
	}

	for _, dp := range dPorts {
		if !kPortMap[dp] {
			msg := fmt.Sprintf(
				"Port mismatch: Dockerfile exposes %s but K8s lacks containerPort %s",
				dp, dp,
			)
			corrs = append(corrs, CoReviewCorrelation{
				ID:          fmt.Sprintf("port-mismatch-%s", dp),
				RuleID:      "coreview-port-mismatch",
				Files:       []string{dockerfilePath, k8sFilePath},
				Message:     msg,
				Severity:    "medium",
				Explanation: "Container ports should align with orchestration target ports",
			})
		}
	}
	return corrs
}

func recordRouteDefect(
	col *Collector,
	filePath, currentPath string,
	lineNum int,
	hasSecurity bool,
) {
	if currentPath != "" && routeAdminRe.MatchString(currentPath) && !hasSecurity {
		col.AddOpenAPI(filePath, "coreview-unauthenticated-endpoint", "high",
			fmt.Sprintf("Sensitive API route %q defined without security schemes", currentPath),
			"Attach authentication middleware or declare security requirements", lineNum)
	}
}

// AnalyzeAPIRoutes checks for unauthenticated administrative endpoints in OpenAPI or route files.
func AnalyzeAPIRoutes(filePath, content string) []ConfigFinding {
	var col Collector
	currentPath := ""
	hasSecurity := false
	routeLines := strings.Split(content, "\n")

	for idx, line := range routeLines {
		no := idx + 1
		trimmed := strings.TrimSpace(line)

		if m := routePathRe.FindStringSubmatch(trimmed); len(m) > 1 {
			recordRouteDefect(&col, filePath, currentPath, no-1, hasSecurity)
			currentPath = m[1]
			hasSecurity = false
		}

		if strings.HasPrefix(trimmed, "security:") || strings.HasPrefix(trimmed, "auth:") {
			hasSecurity = true
		}
	}

	recordRouteDefect(&col, filePath, currentPath, len(routeLines), hasSecurity)
	return col.Results()
}
