// Package iac analyzes Dockerfiles for container security misconfigurations.
package iac

import "regexp"
import "strings"

var (
	addRemoteURLRe = regexp.MustCompile(`(?i)^ADD\s+https?://`)
)

func isSensitiveVar(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "password") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "api_key") ||
		strings.Contains(lower, "private_key")
}

func checkDockerfileLine(col *Collector, file, rawLine, upper string, lineNum int, hasUser *bool) {
	if strings.HasPrefix(upper, "USER ") {
		val := strings.TrimSpace(rawLine[5:])
		*hasUser = (val != "root" && val != "0")
	}

	if strings.HasPrefix(upper, "FROM ") {
		image := strings.TrimSpace(rawLine[5:])
		fields := strings.Fields(image)
		if len(fields) > 0 {
			target := fields[0]
			if !strings.Contains(target, "@") && (!strings.Contains(target, ":") ||
				strings.HasSuffix(target, ":latest")) {
				col.AddDocker(file, "docker-unpinned-base-image", "medium",
					"Base image lacks deterministic version tag or digest pinning",
					"Pin base image with explicit version tag or immutable SHA256 digest", lineNum)
			}
		}
	}

	if addRemoteURLRe.MatchString(rawLine) {
		col.AddDocker(file, "docker-insecure-add", "high",
			"ADD directive fetches unverified remote archive/URL",
			"Use RUN curl/wget with checksum verification or COPY local artifacts", lineNum)
	}

	if strings.HasPrefix(upper, "EXPOSE ") && strings.Contains(rawLine, " 22") {
		col.AddDocker(file, "docker-exposed-ssh", "high",
			"Container exposes SSH port (22)",
			"Do not run SSH daemons inside application containers; use orchestration exec", lineNum)
	}

	if (strings.HasPrefix(upper, "ENV ") || strings.HasPrefix(upper, "ARG ")) &&
		isSensitiveVar(rawLine) && strings.Contains(rawLine, "=") {
		col.AddDocker(file, "docker-hardcoded-secret", "critical",
			"Container build argument or environment variable defines hardcoded secret",
			"Inject secrets at runtime via secret managers or BuildKit secret mounts", lineNum)
	}
}

// AnalyzeDockerfile parses Dockerfile contents and checks container security best practices.
func AnalyzeDockerfile(filePath, content string) []ConfigFinding {
	var col Collector
	hasUser := false
	lineCount := 0

	walkLines(content, func(num int, line string) {
		lineCount = num
		rawLine := strings.TrimSpace(line)
		if rawLine == "" || strings.HasPrefix(rawLine, "#") {
			return
		}
		checkDockerfileLine(&col, filePath, rawLine, strings.ToUpper(rawLine), num, &hasUser)
	})

	if !hasUser && lineCount > 0 {
		col.AddDocker(filePath, "docker-missing-user", "high",
			"Container runs as root user by default; non-root USER instruction missing",
			"Add USER <non-root-user> directive before container entrypoint", 1)
	}

	return col.Results()
}
