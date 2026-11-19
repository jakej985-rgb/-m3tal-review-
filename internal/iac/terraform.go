// Package iac analyzes Terraform configurations for cloud infrastructure security risks.
package iac

import "strings"
import "regexp"

var (
	allIPv4CIDRRe   = regexp.MustCompile(`["']0\.0\.0\.0/0["']`)
	mgmtPortRe      = regexp.MustCompile(`(?:\b(?:from_port|to_port)\s*=\s*(?:22|3389)\b)`)
	wildcardGrantRe = regexp.MustCompile(`(?i)["']?Action["']?\s*[:=]\s*["']\*["']`)
)

// AnalyzeTerraform inspects Terraform HCL/JSON configurations for cloud misconfigurations.
func AnalyzeTerraform(filePath, content string) []ConfigFinding {
	var col Collector
	hasOpenCIDR := false
	hasSensitivePort := false
	s3BucketDeclared := false
	s3Encrypted := false

	tfLines := strings.Split(content, "\n")
	for i, line := range tfLines {
		ln := i + 1
		if strings.Contains(line, `resource "aws_s3_bucket"`) {
			s3BucketDeclared = true
		}
		if strings.Contains(line, "server_side_encryption_configuration") ||
			strings.Contains(line, "aws_s3_bucket_server_side_encryption_configuration") {
			s3Encrypted = true
		}

		if allIPv4CIDRRe.MatchString(line) {
			hasOpenCIDR = true
		}
		if mgmtPortRe.MatchString(line) {
			hasSensitivePort = true
		}

		if hasOpenCIDR && hasSensitivePort {
			col.AddTerraform(filePath, "iac-open-ingress", "critical",
				"Security group rule opens administrative ports (22/3389) to 0.0.0.0/0",
				"Restrict ingress CIDRs to authorized corporate VPN or bastion IP blocks", ln)
			hasOpenCIDR = false
			hasSensitivePort = false
		}

		if wildcardGrantRe.MatchString(line) {
			col.AddTerraform(filePath, "iac-wildcard-iam", "critical",
				"IAM policy statement grants full wildcard actions ('*')",
				"Follow principle of least privilege; scope IAM actions to exact APIs", ln)
		}
	}

	if s3BucketDeclared && !s3Encrypted {
		col.AddTerraform(filePath, "iac-unencrypted-storage", "high",
			"S3 storage bucket declared without server-side encryption configuration",
			"Add server_side_encryption_configuration resource using AES256 or KMS", 1)
	}

	findings := col.Results()
	return findings
}
