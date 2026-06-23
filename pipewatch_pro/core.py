"""Core audit engine for PIPEWATCH-PRO.

Parses CI/CD pipeline definitions (GitHub Actions, GitLab CI) and flags
supply-chain weaknesses mapped to the OWASP CI/CD Top 10. The engine works
on raw text + a light structural pass so it has no third-party YAML
dependency (stdlib only). Detectors are line-accurate where possible.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, asdict
from typing import Iterable


# ---- Tool identity (single source of truth; re-exported by __init__) -------
TOOL_NAME = "PIPEWATCH-PRO"
TOOL_VERSION = "0.3.4"


# Ordered worst -> least for sorting / exit-code decisions.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Filenames / globs that identify CI pipeline definitions.
_GH_WORKFLOW_DIR = os.path.join(".github", "workflows")
_GITLAB_NAMES = {".gitlab-ci.yml", ".gitlab-ci.yaml"}
_YAML_EXTS = (".yml", ".yaml")

# A 40-hex git SHA — the only form of an immutable action pin.
_SHA_PIN = re.compile(r"@[0-9a-f]{40}\b")
# action ref:  uses: owner/repo@ref   (also local ./ and docker:// forms)
_USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)['\"]?", re.IGNORECASE)
_TRIGGER = re.compile(r"^\s*(on|'on')\s*:", re.IGNORECASE)
_RUN_KEY = re.compile(r"^\s*-?\s*run:\s*(.*)$", re.IGNORECASE)
_PERMISSIONS = re.compile(r"^\s*permissions\s*:", re.IGNORECASE)

# curl|bash style remote-execution patterns inside `run:` steps.
_CURL_PIPE_SH = re.compile(
    r"(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b", re.IGNORECASE
)
# Hard-coded secret material assigned in plain text.
_HARDCODED_SECRET = re.compile(
    r"(?i)\b(aws_secret_access_key|api[_-]?key|password|token|secret)\b"
    r"\s*[:=]\s*['\"]?([A-Za-z0-9/+_\-]{16,})['\"]?"
)
# A GitHub token/secret expression embedded directly in an inline script
# (vs. mapped through `env:`), which leaks into process args / logs.
_INLINE_SECRET_EXPR = re.compile(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}")


@dataclass
class Finding:
    rule_id: str          # e.g. "CICD-SEC-04"
    title: str
    severity: str         # critical|high|medium|low|info
    file: str
    line: int             # 1-based; 0 if file-level
    evidence: str
    remediation: str
    owasp: str            # OWASP CICD-SEC reference

    def to_dict(self) -> dict:
        return asdict(self)


def _is_pipeline_file(path: str) -> bool:
    name = os.path.basename(path).lower()
    if name in _GITLAB_NAMES:
        return True
    norm = path.replace("\\", "/").lower()
    if _GH_WORKFLOW_DIR.replace("\\", "/") in norm and name.endswith(_YAML_EXTS):
        return True
    return False


def discover_pipeline_files(root: str) -> list[str]:
    """Walk *root* and return every recognised CI pipeline file."""
    if os.path.isfile(root):
        return [root] if root else []
    found: list[str] = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            full = os.path.join(dirpath, fn)
            if _is_pipeline_file(full):
                found.append(full)
    return sorted(found)


def _strip_comment(line: str) -> str:
    # Naive but effective: drop trailing `# ...` not inside quotes.
    in_s = in_d = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d:
            return line[:i]
    return line


def _looks_like_action_ref(ref: str) -> bool:
    # owner/repo[/path]@ref — exclude local (./) and docker:// composites.
    if ref.startswith("./") or ref.startswith("../") or ref.startswith("docker://"):
        return False
    return "@" in ref and "/" in ref.split("@", 1)[0]


def audit_text(text: str, path: str) -> list[Finding]:
    """Run all detectors over a single pipeline document."""
    findings: list[Finding] = []
    lines = text.splitlines()
    is_gitlab = os.path.basename(path).lower() in _GITLAB_NAMES
    has_permissions_block = any(_PERMISSIONS.match(l) for l in lines)
    has_trigger = any(_TRIGGER.match(_strip_comment(l)) for l in lines)
    pull_request_target = False

    for idx, raw in enumerate(lines, start=1):
        line = _strip_comment(raw)
        if not line.strip():
            continue

        # --- CICD-SEC-04: Poisoned Pipeline Execution / unpinned actions ---
        m = _USES.match(line)
        if m:
            ref = m.group(1).strip()
            if _looks_like_action_ref(ref):
                tag = ref.split("@", 1)[1]
                if not _SHA_PIN.search(ref):
                    sev = "high"
                    if tag in ("main", "master", "latest"):
                        # branch/floating ref — can be force-pushed under you
                        sev = "critical"
                    findings.append(Finding(
                        rule_id="CICD-SEC-04",
                        title="Action not pinned to a full commit SHA",
                        severity=sev,
                        file=path, line=idx, evidence=ref,
                        remediation=(
                            "Pin to a full 40-char commit SHA "
                            "(e.g. uses: owner/repo@<sha>  # tag) instead of a "
                            "mutable tag/branch that can be retargeted."),
                        owasp="CICD-SEC-04 Poisoned Pipeline Execution",
                    ))

        # --- CICD-SEC-07: Insecure System Configuration (curl|bash) ---
        rm = _RUN_KEY.match(line)
        run_body = rm.group(1) if rm else line
        if _CURL_PIPE_SH.search(run_body):
            findings.append(Finding(
                rule_id="CICD-SEC-07",
                title="Remote script piped directly into a shell",
                severity="high",
                file=path, line=idx,
                evidence=run_body.strip()[:160],
                remediation=(
                    "Download to a file, verify a checksum/signature, then "
                    "execute. Piping curl|bash runs unverified remote code."),
                owasp="CICD-SEC-07 Insecure System Configuration",
            ))

        # --- CICD-SEC-06: Insufficient Credential Hygiene (hardcoded) ---
        hm = _HARDCODED_SECRET.search(line)
        if hm and "${{" not in line and "$(" not in line and "secrets." not in line:
            val = hm.group(2)
            # Avoid flagging obvious placeholders.
            if not re.fullmatch(r"(x{8,}|changeme|placeholder|example.*|<.*>)", val, re.IGNORECASE):
                findings.append(Finding(
                    rule_id="CICD-SEC-06",
                    title="Hard-coded credential in pipeline",
                    severity="critical",
                    file=path, line=idx,
                    evidence=re.sub(re.escape(val), val[:4] + "…(redacted)", line.strip())[:160],
                    remediation=(
                        "Move the secret to the platform secret store "
                        "(GitHub/GitLab secrets) and reference it at runtime."),
                    owasp="CICD-SEC-06 Insufficient Credential Hygiene",
                ))

        # --- CICD-SEC-06: secret expression interpolated into inline script ---
        if rm and _INLINE_SECRET_EXPR.search(run_body):
            findings.append(Finding(
                rule_id="CICD-SEC-06",
                title="Secret interpolated directly into run script",
                severity="medium",
                file=path, line=idx,
                evidence=run_body.strip()[:160],
                remediation=(
                    "Pass secrets via the step `env:` map, not string "
                    "interpolation, to avoid leaking them into shell args/logs."),
                owasp="CICD-SEC-06 Insufficient Credential Hygiene",
            ))

        # --- CICD-SEC-01: Insufficient Flow Control (pull_request_target) ---
        if re.search(r"\bpull_request_target\b", line):
            pull_request_target = True

    # ---- File-level findings ---------------------------------------------

    # CICD-SEC-05: Insufficient PBAC — no least-privilege token scope (GH only)
    if not is_gitlab and has_trigger and not has_permissions_block:
        findings.append(Finding(
            rule_id="CICD-SEC-05",
            title="No explicit `permissions:` block (token defaults to broad scope)",
            severity="medium",
            file=path, line=0,
            evidence="workflow has no top-level or job-level permissions:",
            remediation=(
                "Add `permissions: { contents: read }` and grant only the "
                "scopes each job needs; the default GITHUB_TOKEN is over-privileged."),
            owasp="CICD-SEC-05 Insufficient PBAC",
        ))

    # CICD-SEC-01: pull_request_target without an explicit ref checkout guard.
    if pull_request_target:
        findings.append(Finding(
            rule_id="CICD-SEC-01",
            title="`pull_request_target` trigger exposes secrets to fork PRs",
            severity="high",
            file=path, line=0,
            evidence="on: pull_request_target",
            remediation=(
                "pull_request_target runs with repo secrets in the PR context. "
                "Avoid checking out / executing untrusted PR head code, or "
                "switch to `pull_request`."),
            owasp="CICD-SEC-01 Insufficient Flow Control Mechanisms",
        ))

    return findings


def audit_file(path: str) -> list[Finding]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    return audit_text(text, path)


def audit_paths(paths: Iterable[str]) -> list[Finding]:
    """Audit each path; directories are walked for pipeline files."""
    all_findings: list[Finding] = []
    targets: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            targets.extend(discover_pipeline_files(p))
        elif os.path.isfile(p):
            targets.append(p)
        else:
            raise FileNotFoundError(p)
    for t in targets:
        all_findings.extend(audit_file(t))
    all_findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line))
    return all_findings


def scan(paths) -> list[dict]:
    """Convenience wrapper returning plain dicts (used by the MCP server)."""
    if isinstance(paths, str):
        paths = [paths]
    return [f.to_dict() for f in audit_paths(paths)]


# Map our internal severities to SARIF result levels.
_SARIF_LEVEL = {
    "critical": "error", "high": "error", "medium": "warning",
    "low": "note", "info": "note",
}


def to_sarif(findings: list[Finding]) -> dict:
    """Render findings as a SARIF 2.1.0 log (GitHub code-scanning compatible)."""
    rule_index: dict[str, int] = {}
    rules: list[dict] = []
    results: list[dict] = []
    for f in findings:
        if f.rule_id not in rule_index:
            rule_index[f.rule_id] = len(rules)
            rules.append({
                "id": f.rule_id,
                "name": f.rule_id.replace("-", ""),
                "shortDescription": {"text": f.title},
                "helpUri": "https://owasp.org/www-project-top-10-ci-cd-security-risks/",
                "properties": {"owasp": f.owasp},
            })
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": rule_index[f.rule_id],
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.title} — {f.remediation}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file.replace("\\", "/")},
                    "region": {"startLine": max(f.line, 1)},
                }
            }],
            "properties": {"severity": f.severity, "evidence": f.evidence},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": "https://github.com/cognis-digital/pipewatch-pro",
                "rules": rules,
            }},
            "results": results,
        }],
    }


# --- Component extraction (for offline CVE enrichment) ----------------------
# A Docker image reference inside a workflow:  image: owner/name:tag
_IMAGE = re.compile(
    r"^\s*-?\s*image\s*:\s*['\"]?([A-Za-z0-9][\w./-]*?):([\w.\-]+)['\"]?",
    re.IGNORECASE,
)
# `uses: owner/repo@ref` — the action's repo is the component.
# pip/npm pinned installs inside run: steps,  e.g.  pip install requests==2.5.0
_PIN_PIP = re.compile(r"\b([A-Za-z0-9][\w.\-]+)==([\w.\-]+)")
_PIN_NPM = re.compile(r"\b([@A-Za-z0-9][\w./\-]+)@(\d[\w.\-]*)")
# Bare CVE / GHSA reference anywhere in the text.
_CVE_REF = re.compile(r"\b(CVE-\d{4}-\d{3,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b",
                      re.IGNORECASE)


@dataclass
class Component:
    name: str
    version: str
    kind: str          # action|image|pip|npm|cve-ref
    file: str
    line: int

    def to_dict(self) -> dict:
        return asdict(self)


def extract_components(text: str, path: str) -> list[Component]:
    """Pull named software components + CVE refs from a pipeline document.

    Purely textual / offline — feeds the `enrich` subcommand which matches each
    component name against the bundled OSV vulnerability database.
    """
    out: list[Component] = []
    seen: set[tuple] = set()

    def _add(name: str, version: str, kind: str, line: int) -> None:
        key = (name.lower(), version, kind)
        if name and key not in seen:
            seen.add(key)
            out.append(Component(name, version, kind, path, line))

    for idx, raw in enumerate(text.splitlines(), start=1):
        # CVE/GHSA refs are valid even inside comments (advisory annotations) —
        # scan the raw line first, before the blank/comment skip below.
        for cm in _CVE_REF.finditer(raw):
            _add(cm.group(1).upper(), "", "cve-ref", idx)
        line = _strip_comment(raw)
        if not line.strip():
            continue
        m = _USES.match(line)
        if m and _looks_like_action_ref(m.group(1).strip()):
            ref = m.group(1).strip()
            repo, _, tag = ref.partition("@")
            _add(repo, tag, "action", idx)
        im = _IMAGE.match(line)
        if im:
            _add(im.group(1), im.group(2), "image", idx)
        rm = _RUN_KEY.match(line)
        body = rm.group(1) if rm else line
        if "install" in body.lower():
            for pm in _PIN_PIP.finditer(body):
                _add(pm.group(1), pm.group(2), "pip", idx)
            if "npm" in body.lower() or "yarn" in body.lower():
                for nm in _PIN_NPM.finditer(body):
                    _add(nm.group(1), nm.group(2), "npm", idx)
    return out


def summarize(findings: list[Finding]) -> dict:
    by_sev: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_sev,
        "by_rule": by_rule,
        # gating: critical/high cause failure
        "failed": sum(by_sev.get(s, 0) for s in ("critical", "high")),
    }
