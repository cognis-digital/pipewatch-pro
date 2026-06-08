"""Command-line interface for PIPEWATCH-PRO."""
from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import audit_paths, summarize, SEVERITY_ORDER


_SEV_GLYPH = {
    "critical": "CRIT", "high": "HIGH", "medium": "MED ",
    "low": "LOW ", "info": "INFO",
}


def _render_table(findings, summary) -> str:
    lines: list[str] = []
    lines.append(f"{TOOL_NAME} {TOOL_VERSION} - CI/CD supply-chain audit")
    lines.append("=" * 64)
    if not findings:
        lines.append("No findings. Pipelines pass the OWASP CI/CD checks.")
        return "\n".join(lines)
    for f in findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        lines.append(f"[{_SEV_GLYPH.get(f.severity, f.severity)}] {f.rule_id}  {f.title}")
        lines.append(f"        at {loc}")
        lines.append(f"        evidence: {f.evidence}")
        lines.append(f"        fix: {f.remediation}")
        lines.append("")
    lines.append("-" * 64)
    sev = summary["by_severity"]
    parts = [f"{k}={sev[k]}" for k in sorted(sev, key=lambda s: SEVERITY_ORDER.get(s, 9))]
    lines.append(f"Total: {summary['total']}  ({', '.join(parts)})")
    lines.append(f"Gating (critical+high): {summary['failed']}")
    return "\n".join(lines)


def _cmd_audit(args) -> int:
    try:
        findings = audit_paths(args.paths)
    except FileNotFoundError as exc:
        print(f"error: path not found: {exc}", file=sys.stderr)
        return 2
    summary = summarize(findings)

    if args.format == "json":
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "summary": summary,
            "findings": [f.to_dict() for f in findings],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(_render_table(findings, summary))

    # Fail the build when findings at/above the threshold exist.
    if args.fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    worst_hit = any(SEVERITY_ORDER.get(f.severity, 9) <= threshold for f in findings)
    return 1 if worst_hit else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pipewatch-pro",
        description="Audit CI/CD pipelines against the OWASP CI/CD Top 10.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("audit", help="Audit pipeline files / directories.")
    a.add_argument("paths", nargs="+",
                   help="Files or directories (repos) to scan.")
    a.add_argument("--format", choices=("table", "json"), default="table")
    a.add_argument("--fail-on",
                   choices=("critical", "high", "medium", "low", "info", "never"),
                   default="high", metavar="SEVERITY",
                   help="Exit non-zero if a finding at/above this severity "
                        "exists, or 'never' to always exit 0. Default: high.")
    a.set_defaults(func=_cmd_audit)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
