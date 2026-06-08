"""PIPEWATCH-PRO — auto-generated detector core."""
from __future__ import annotations
import re, time
from pathlib import Path
from cognis_core import Finding, ScanResult, score

TOOL_NAME = "PIPEWATCH-PRO"
TOOL_VERSION = "0.1.0"

PATTERNS = [('PW-ACT-001', 'high', 2.5, 'UNPINNED_ACTION', 'uses:\\s+[a-zA-Z0-9_./-]+@(main|master|v\\d+)$', 'Pin to a full commit SHA (immutable).'), ('PW-SECRET-001', 'critical', 3.0, 'SECRET_IN_ENV', '(?i)env:\\s*\\n\\s+[A-Z_]+_TOKEN:\\s*[A-Za-z0-9]{20,}', 'Move to encrypted secret store; never inline.'), ('PW-PERM-001', 'high', 2.5, 'NO_PERMISSIONS_BLOCK', '^(?!.*permissions:)', 'Add explicit least-privilege `permissions:` block.')]
FILE_GLOBS = ['.github/workflows/*.yml', '*.yml', '*.yaml']

def scan(target: str, **opts) -> ScanResult:
    t0 = time.time()
    result = ScanResult(tool_name=TOOL_NAME, tool_version=TOOL_VERSION, target=str(target))
    p = Path(target)
    files: list[Path] = []
    if p.is_dir():
        for g in FILE_GLOBS:
            files.extend(p.rglob(g))
    elif p.is_file():
        files = [p]
    result.items_scanned = len(files)
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for rid,sev,w,title,pat,rem in PATTERNS:
            for m in re.finditer(pat, text):
                line = text.count(chr(10), 0, m.start()) + 1
                result.add(Finding(
                    id=rid, severity=sev, weight=w, title=title,
                    description=f"{title}: `{m.group(0)[:80]}`",
                    location=f"{f}:{line}", remediation=rem, category="cicd-supply-chain",
                ))
    result.composite_score, result.risk_level = score(result.findings)
    result.scan_duration_ms = int((time.time()-t0)*1000)
    return result
