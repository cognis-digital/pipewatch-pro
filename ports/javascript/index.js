#!/usr/bin/env node
// PIPEWATCH-PRO — Node.js port of the CI/CD pipeline auditor.
//
// Mirrors the primary `audit` command of the Python tool: walks a target,
// finds GitHub Actions / GitLab CI pipeline files, and flags supply-chain
// weaknesses mapped to the OWASP CI/CD Top 10. Zero dependencies, stdlib only.
// Passive and offline — reads files, never scans a network.
//
//   node index.js <path>                 # table output
//   node index.js --format json <path>
import fs from "node:fs";
import path from "node:path";

export const TOOL_NAME = "PIPEWATCH-PRO";
export const TOOL_VERSION = "0.3.4";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const RE_SHA_PIN = /@[0-9a-f]{40}\b/;
const RE_USES = /^\s*-?\s*uses:\s*['"]?([^'"\s#]+)/i;
const RE_TRIGGER = /^\s*('?on'?)\s*:/i;
const RE_RUN = /^\s*-?\s*run:\s*(.*)$/i;
const RE_PERMISSIONS = /^\s*permissions\s*:/i;
const RE_CURL_PIPE_SH = /(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b/i;
const RE_HARDCODED =
  /\b(aws_secret_access_key|api[_-]?key|password|token|secret)\b\s*[:=]\s*['"]?([A-Za-z0-9/+_\-]{16,})['"]?/i;
const RE_INLINE_SECRET = /\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}/;
const RE_PLACEHOLDER = /^(x{8,}|changeme|placeholder|example.*|<.*>)$/i;

function stripComment(line) {
  let inS = false,
    inD = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === "'" && !inD) inS = !inS;
    else if (ch === '"' && !inS) inD = !inD;
    else if (ch === "#" && !inS && !inD) return line.slice(0, i);
  }
  return line;
}

function looksLikeActionRef(ref) {
  if (ref.startsWith("./") || ref.startsWith("../") || ref.startsWith("docker://"))
    return false;
  return ref.includes("@") && ref.split("@", 1)[0].includes("/");
}

function isGitlab(p) {
  const b = path.basename(p).toLowerCase();
  return b === ".gitlab-ci.yml" || b === ".gitlab-ci.yaml";
}

function isPipelineFile(p) {
  if (isGitlab(p)) return true;
  const norm = p.replace(/\\/g, "/").toLowerCase();
  return (
    norm.includes(".github/workflows/") &&
    (norm.endsWith(".yml") || norm.endsWith(".yaml"))
  );
}

export function auditText(text, filePath) {
  const findings = [];
  const lines = text.split("\n");
  const gitlab = isGitlab(filePath);
  const hasPerms = lines.some((l) => RE_PERMISSIONS.test(l));
  const hasTrigger = lines.some((l) => RE_TRIGGER.test(stripComment(l)));
  let prTarget = false;

  lines.forEach((raw, i) => {
    const idx = i + 1;
    const line = stripComment(raw);
    if (!line.trim()) return;

    const m = line.match(RE_USES);
    if (m && looksLikeActionRef(m[1].trim())) {
      const ref = m[1].trim();
      if (!RE_SHA_PIN.test(ref)) {
        const tag = ref.split("@")[1];
        const sev = ["main", "master", "latest"].includes(tag) ? "critical" : "high";
        findings.push({
          rule_id: "CICD-SEC-04",
          title: "Action not pinned to a full commit SHA",
          severity: sev,
          file: filePath,
          line: idx,
          evidence: ref,
          remediation: "Pin to a full 40-char commit SHA instead of a mutable tag/branch.",
          owasp: "CICD-SEC-04 Poisoned Pipeline Execution",
        });
      }
    }

    const rm = line.match(RE_RUN);
    const runBody = rm ? rm[1] : line;
    if (RE_CURL_PIPE_SH.test(runBody)) {
      findings.push({
        rule_id: "CICD-SEC-07",
        title: "Remote script piped directly into a shell",
        severity: "high",
        file: filePath,
        line: idx,
        evidence: runBody.trim().slice(0, 160),
        remediation: "Download to a file, verify a checksum/signature, then execute.",
        owasp: "CICD-SEC-07 Insecure System Configuration",
      });
    }

    const hm = line.match(RE_HARDCODED);
    if (hm && !line.includes("${{") && !line.includes("$(") && !line.includes("secrets.")) {
      const val = hm[2];
      if (!RE_PLACEHOLDER.test(val)) {
        const redacted = line.trim().replace(val, val.slice(0, 4) + "…(redacted)");
        findings.push({
          rule_id: "CICD-SEC-06",
          title: "Hard-coded credential in pipeline",
          severity: "critical",
          file: filePath,
          line: idx,
          evidence: redacted.slice(0, 160),
          remediation: "Move the secret to the platform secret store and reference it at runtime.",
          owasp: "CICD-SEC-06 Insufficient Credential Hygiene",
        });
      }
    }

    if (rm && RE_INLINE_SECRET.test(runBody)) {
      findings.push({
        rule_id: "CICD-SEC-06",
        title: "Secret interpolated directly into run script",
        severity: "medium",
        file: filePath,
        line: idx,
        evidence: runBody.trim().slice(0, 160),
        remediation: "Pass secrets via the step env: map, not string interpolation.",
        owasp: "CICD-SEC-06 Insufficient Credential Hygiene",
      });
    }

    if (line.includes("pull_request_target")) prTarget = true;
  });

  if (!gitlab && hasTrigger && !hasPerms) {
    findings.push({
      rule_id: "CICD-SEC-05",
      title: "No explicit permissions: block (token defaults to broad scope)",
      severity: "medium",
      file: filePath,
      line: 0,
      evidence: "workflow has no top-level or job-level permissions:",
      remediation: "Add permissions: { contents: read } and grant only needed scopes.",
      owasp: "CICD-SEC-05 Insufficient PBAC",
    });
  }
  if (prTarget) {
    findings.push({
      rule_id: "CICD-SEC-01",
      title: "pull_request_target trigger exposes secrets to fork PRs",
      severity: "high",
      file: filePath,
      line: 0,
      evidence: "on: pull_request_target",
      remediation: "Avoid checking out / executing untrusted PR head code, or use pull_request.",
      owasp: "CICD-SEC-01 Insufficient Flow Control Mechanisms",
    });
  }
  return findings;
}

function walk(root) {
  const out = [];
  let st;
  try {
    st = fs.statSync(root);
  } catch {
    return out;
  }
  if (!st.isDirectory()) return [root];
  for (const e of fs.readdirSync(root, { withFileTypes: true })) {
    const full = path.join(root, e.name);
    if (e.isDirectory()) out.push(...walk(full));
    else if (isPipelineFile(full)) out.push(full);
  }
  return out.sort();
}

export function summarize(findings) {
  const bySev = {};
  for (const f of findings) bySev[f.severity] = (bySev[f.severity] || 0) + 1;
  return {
    total: findings.length,
    by_severity: bySev,
    failed: (bySev.critical || 0) + (bySev.high || 0),
  };
}

function main(argv) {
  let format = "table";
  const paths = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--format") format = argv[++i];
    else if (argv[i] === "--version") {
      console.log(`${TOOL_NAME} ${TOOL_VERSION}`);
      return 0;
    } else paths.push(argv[i]);
  }
  if (!paths.length) paths.push(".");

  let all = [];
  for (const p of paths)
    for (const f of walk(p)) all.push(...auditText(fs.readFileSync(f, "utf8"), f));
  all.sort(
    (a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) ||
      a.file.localeCompare(b.file),
  );
  const summary = summarize(all);

  if (format === "json") {
    console.log(JSON.stringify({ tool: TOOL_NAME, version: TOOL_VERSION, summary, findings: all }, null, 2));
  } else {
    console.log(`${TOOL_NAME} ${TOOL_VERSION} - CI/CD supply-chain audit`);
    for (const f of all)
      console.log(`[${f.severity.padEnd(8)}] ${f.rule_id}  ${f.title}\n        at ${f.file}:${f.line}`);
    console.log(`Total: ${summary.total}  Gating (critical+high): ${summary.failed}`);
  }
  return summary.failed > 0 ? 1 : 0;
}

const invoked = process.argv[1] && path.basename(process.argv[1]) === "index.js";
if (invoked) {
  process.exit(main(process.argv.slice(2)));
}
