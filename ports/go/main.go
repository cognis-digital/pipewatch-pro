// PIPEWATCH-PRO — Go port of the CI/CD pipeline auditor.
//
// Mirrors the primary `audit` command of the Python tool: it walks a target,
// finds GitHub Actions / GitLab CI pipeline files, and flags supply-chain
// weaknesses mapped to the OWASP CI/CD Top 10. Single binary, zero deps,
// stdlib only. Passive and offline — it reads files, it never scans a network.
//
//	go run ./ports/go <path>            # table output
//	go run ./ports/go --format json <path>
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const toolName = "PIPEWATCH-PRO"
const toolVersion = "0.3.4"

// Finding mirrors the Python dataclass field-for-field.
type Finding struct {
	RuleID      string `json:"rule_id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
	OWASP       string `json:"owasp"`
}

var severityOrder = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}

var (
	reSHAPin       = regexp.MustCompile(`@[0-9a-f]{40}\b`)
	reUses         = regexp.MustCompile(`(?i)^\s*-?\s*uses:\s*['"]?([^'"\s#]+)`)
	reTrigger      = regexp.MustCompile(`(?i)^\s*('?on'?)\s*:`)
	reRun          = regexp.MustCompile(`(?i)^\s*-?\s*run:\s*(.*)$`)
	rePermissions  = regexp.MustCompile(`(?i)^\s*permissions\s*:`)
	reCurlPipeSh   = regexp.MustCompile(`(?i)(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b`)
	reHardcoded    = regexp.MustCompile(`(?i)\b(aws_secret_access_key|api[_-]?key|password|token|secret)\b\s*[:=]\s*['"]?([A-Za-z0-9/+_\-]{16,})['"]?`)
	reInlineSecret = regexp.MustCompile(`\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}`)
	rePlaceholder  = regexp.MustCompile(`(?i)^(x{8,}|changeme|placeholder|example.*|<.*>)$`)
)

func stripComment(line string) string {
	inS, inD := false, false
	for i, ch := range line {
		switch {
		case ch == '\'' && !inD:
			inS = !inS
		case ch == '"' && !inS:
			inD = !inD
		case ch == '#' && !inS && !inD:
			return line[:i]
		}
	}
	return line
}

func looksLikeActionRef(ref string) bool {
	if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "../") || strings.HasPrefix(ref, "docker://") {
		return false
	}
	if !strings.Contains(ref, "@") {
		return false
	}
	return strings.Contains(strings.SplitN(ref, "@", 2)[0], "/")
}

func isGitlab(path string) bool {
	b := strings.ToLower(filepath.Base(path))
	return b == ".gitlab-ci.yml" || b == ".gitlab-ci.yaml"
}

func isPipelineFile(path string) bool {
	if isGitlab(path) {
		return true
	}
	norm := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	if strings.Contains(norm, ".github/workflows/") &&
		(strings.HasSuffix(norm, ".yml") || strings.HasSuffix(norm, ".yaml")) {
		return true
	}
	return false
}

func auditText(text, path string) []Finding {
	var fs []Finding
	lines := strings.Split(text, "\n")
	gitlab := isGitlab(path)
	hasPerms, hasTrigger, prTarget := false, false, false
	for _, l := range lines {
		if rePermissions.MatchString(l) {
			hasPerms = true
		}
		if reTrigger.MatchString(stripComment(l)) {
			hasTrigger = true
		}
	}

	for i, raw := range lines {
		idx := i + 1
		line := stripComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}
		if m := reUses.FindStringSubmatch(line); m != nil {
			ref := strings.TrimSpace(m[1])
			if looksLikeActionRef(ref) && !reSHAPin.MatchString(ref) {
				tag := strings.SplitN(ref, "@", 2)[1]
				sev := "high"
				if tag == "main" || tag == "master" || tag == "latest" {
					sev = "critical"
				}
				fs = append(fs, Finding{"CICD-SEC-04", "Action not pinned to a full commit SHA",
					sev, path, idx, ref,
					"Pin to a full 40-char commit SHA instead of a mutable tag/branch.",
					"CICD-SEC-04 Poisoned Pipeline Execution"})
			}
		}
		runBody := line
		if m := reRun.FindStringSubmatch(line); m != nil {
			runBody = m[1]
		}
		if reCurlPipeSh.MatchString(runBody) {
			fs = append(fs, Finding{"CICD-SEC-07", "Remote script piped directly into a shell",
				"high", path, idx, trunc(strings.TrimSpace(runBody), 160),
				"Download to a file, verify a checksum/signature, then execute.",
				"CICD-SEC-07 Insecure System Configuration"})
		}
		if hm := reHardcoded.FindStringSubmatch(line); hm != nil &&
			!strings.Contains(line, "${{") && !strings.Contains(line, "$(") &&
			!strings.Contains(line, "secrets.") {
			val := hm[2]
			if !rePlaceholder.MatchString(val) {
				redacted := strings.Replace(strings.TrimSpace(line), val, val[:4]+"…(redacted)", 1)
				fs = append(fs, Finding{"CICD-SEC-06", "Hard-coded credential in pipeline",
					"critical", path, idx, trunc(redacted, 160),
					"Move the secret to the platform secret store and reference it at runtime.",
					"CICD-SEC-06 Insufficient Credential Hygiene"})
			}
		}
		if reRun.MatchString(line) && reInlineSecret.MatchString(runBody) {
			fs = append(fs, Finding{"CICD-SEC-06", "Secret interpolated directly into run script",
				"medium", path, idx, trunc(strings.TrimSpace(runBody), 160),
				"Pass secrets via the step env: map, not string interpolation.",
				"CICD-SEC-06 Insufficient Credential Hygiene"})
		}
		if strings.Contains(line, "pull_request_target") {
			prTarget = true
		}
	}

	if !gitlab && hasTrigger && !hasPerms {
		fs = append(fs, Finding{"CICD-SEC-05",
			"No explicit permissions: block (token defaults to broad scope)",
			"medium", path, 0, "workflow has no top-level or job-level permissions:",
			"Add permissions: { contents: read } and grant only needed scopes.",
			"CICD-SEC-05 Insufficient PBAC"})
	}
	if prTarget {
		fs = append(fs, Finding{"CICD-SEC-01",
			"pull_request_target trigger exposes secrets to fork PRs",
			"high", path, 0, "on: pull_request_target",
			"Avoid checking out / executing untrusted PR head code, or use pull_request.",
			"CICD-SEC-01 Insufficient Flow Control Mechanisms"})
	}
	return fs
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func discover(root string) []string {
	var found []string
	info, err := os.Stat(root)
	if err == nil && !info.IsDir() {
		return []string{root}
	}
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		if isPipelineFile(p) {
			found = append(found, p)
		}
		return nil
	})
	sort.Strings(found)
	return found
}

func main() {
	args := os.Args[1:]
	format := "table"
	var paths []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--format" && i+1 < len(args) {
			format = args[i+1]
			i++
		} else if args[i] == "--version" {
			fmt.Printf("%s %s\n", toolName, toolVersion)
			return
		} else {
			paths = append(paths, args[i])
		}
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}

	var all []Finding
	for _, p := range paths {
		for _, f := range discover(p) {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			all = append(all, auditText(string(b), f)...)
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if severityOrder[all[i].Severity] != severityOrder[all[j].Severity] {
			return severityOrder[all[i].Severity] < severityOrder[all[j].Severity]
		}
		return all[i].File < all[j].File
	})

	bySev := map[string]int{}
	failed := 0
	for _, f := range all {
		bySev[f.Severity]++
		if f.Severity == "critical" || f.Severity == "high" {
			failed++
		}
	}

	if format == "json" {
		out, _ := json.MarshalIndent(map[string]any{
			"tool": toolName, "version": toolVersion,
			"summary":  map[string]any{"total": len(all), "by_severity": bySev, "failed": failed},
			"findings": all,
		}, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Printf("%s %s - CI/CD supply-chain audit\n", toolName, toolVersion)
		for _, f := range all {
			fmt.Printf("[%-8s] %s  %s\n        at %s:%d\n", f.Severity, f.RuleID, f.Title, f.File, f.Line)
		}
		fmt.Printf("Total: %d  Gating (critical+high): %d\n", len(all), failed)
	}
	if failed > 0 {
		os.Exit(1)
	}
}
