// Package iac analyzes Kubernetes manifests for security and reliability misconfigurations.
package iac

import "regexp"
import "strings"

var (
	isPrivilegedRe = regexp.MustCompile(`(?i)^\s*privileged:\s*true\b`)
	isHostScopeRe  = regexp.MustCompile(`(?i)^\s*host(?:PID|Network|IPC):\s*true\b`)
	isZeroUIDRe    = regexp.MustCompile(`(?i)^\s*runAsUser:\s*0\b`)
)

func evaluateK8sLine(col *Collector, file, line string, num int) {
	if isPrivilegedRe.MatchString(line) {
		col.AddK8s(file, "k8s-privileged-container", "critical",
			"Container runs in privileged mode, granting full host root access",
			"Set privileged: false and grant only specific Linux capabilities", num)
	}

	if isHostScopeRe.MatchString(line) {
		col.AddK8s(file, "k8s-host-namespace", "high",
			"Pod shares host process, network, or IPC namespace",
			"Disable hostPID, hostNetwork, and hostIPC to preserve node isolation", num)
	}

	if isZeroUIDRe.MatchString(line) {
		col.AddK8s(file, "k8s-root-container", "high",
			"Container explicitly runs with root UID (runAsUser: 0)",
			"Configure runAsNonRoot: true and specify non-zero runAsUser", num)
	}
}

// AnalyzeKubernetes inspects a Kubernetes deployment or pod manifest for security misconfigurations.
func AnalyzeKubernetes(filePath, content string) []ConfigFinding {
	var col Collector
	hasResources := false
	isManifest := false
	manifestLines := strings.Split(content, "\n")

	for idx, text := range manifestLines {
		no := idx + 1
		stripped := strings.TrimSpace(text)

		if strings.HasPrefix(stripped, "apiVersion:") || strings.HasPrefix(stripped, "kind:") {
			isManifest = true
		}
		if strings.HasPrefix(stripped, "resources:") || strings.HasPrefix(stripped, "limits:") {
			hasResources = true
		}

		evaluateK8sLine(&col, filePath, text, no)
	}

	if isManifest && !hasResources && len(manifestLines) > 0 {
		col.AddK8s(filePath, "k8s-missing-resource-limits", "medium",
			"Container manifest lacks CPU and memory resource limits",
			"Define resources.limits.cpu and resources.limits.memory to prevent DoS", 1)
	}

	out := col.Results()
	return out
}
