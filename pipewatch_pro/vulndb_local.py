"""cognis_vulndb — a bundled, offline, 260k+ real-vulnerability database.

Ships a consolidated compact OSV corpus (cognis_vulndb.jsonl.gz, ~262k real
vulns across PyPI/npm/Go/Maven/RubyGems/crates.io/NuGet) with detailed metadata
per record: id, CVE/GHSA aliases, ecosystem, summary, severity (CVSS), affected
packages, published/modified dates, reference count. Pure standard library; works
fully offline / air-gapped — no network, no key.

    from vulndb_local import VulnDB
    db = VulnDB()                       # lazy-loads the bundled gz
    db.count()                          # -> 262351
    db.by_cve("CVE-2021-44228")         # -> [records ...]
    db.by_package("log4j-core")         # -> records affecting that package
    db.search("deserialization", 20)    # -> summary substring matches

Refresh/extend the corpus with `datafeeds.py bulk` (OSV/NVD/GHSA) — this bundle
is the offline baseline so the tool has 100k+ vulns the moment it's cloned.
"""

from __future__ import annotations

import gzip
import json
import os
from pathlib import Path
from typing import Any, Iterator, Optional

_HERE = Path(__file__).resolve().parent
_DB = _HERE / "cognis_vulndb.jsonl.gz"


class VulnDB:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path) if path else _DB
        self._records: Optional[list[dict]] = None
        self._by_cve: Optional[dict[str, list[dict]]] = None
        self._by_pkg: Optional[dict[str, list[dict]]] = None

    # ----- loading -----------------------------------------------------
    def __iter__(self) -> Iterator[dict]:
        if self._records is not None:
            yield from self._records
            return
        if not self.path.exists():
            return
        with gzip.open(self.path, "rt", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def load(self) -> list[dict]:
        if self._records is None:
            self._records = list(self)
        return self._records

    def count(self) -> int:
        return len(self.load())

    # ----- indexed lookups (built lazily on first use) -----------------
    def _index(self) -> None:
        if self._by_cve is not None:
            return
        self._by_cve, self._by_pkg = {}, {}
        for r in self.load():
            for alias in (r.get("aliases") or []):
                self._by_cve.setdefault(alias.upper(), []).append(r)
            if r.get("id"):
                self._by_cve.setdefault(r["id"].upper(), []).append(r)
            for p in (r.get("packages") or []):
                if p:
                    self._by_pkg.setdefault(p.lower(), []).append(r)

    def by_cve(self, cve: str) -> list[dict]:
        self._index()
        return self._by_cve.get((cve or "").upper(), [])

    def by_package(self, name: str, ecosystem: Optional[str] = None) -> list[dict]:
        self._index()
        hits = self._by_pkg.get((name or "").lower(), [])
        if ecosystem:
            hits = [r for r in hits if r.get("ecosystem", "").lower() == ecosystem.lower()]
        return hits

    def search(self, text: str, limit: int = 50) -> list[dict]:
        t = (text or "").lower()
        out = []
        for r in self:
            if t in (r.get("summary", "") or "").lower():
                out.append(r)
                if len(out) >= limit:
                    break
        return out


    # ----- convenience helpers ----------------------------------------
    def cve_aliases(self, record: dict) -> list[str]:
        """All CVE/GHSA identifiers for a record (id + aliases)."""
        ids = [record.get("id", "")] + list(record.get("aliases") or [])
        return [i for i in ids if i]

    def package_match(self, name: str, ecosystem: Optional[str] = None) -> list[dict]:
        """Match a component name against package strings, tolerant of the
        ``group:artifact`` (Maven) / ``@scope/pkg`` (npm) forms in the corpus.

        Falls back to a suffix match on the artifact id so e.g. ``log4j-core``
        resolves the Maven ``org.apache.logging.log4j:log4j-core`` records.
        """
        exact = self.by_package(name, ecosystem)
        if exact:
            return exact
        self._index()
        n = (name or "").lower()
        if not n:
            return []
        hits: list[dict] = []
        seen: set[int] = set()
        for key, recs in self._by_pkg.items():
            artifact = key.split(":")[-1].split("/")[-1]
            if artifact == n:
                for r in recs:
                    if id(r) not in seen and (
                        not ecosystem or r.get("ecosystem", "").lower() == ecosystem.lower()
                    ):
                        seen.add(id(r))
                        hits.append(r)
        return hits


# CVSS v3/v4 base-score band -> coarse severity label (no scoring needed:
# we read the embedded vector's published band where present).
def severity_band(cvss_vector: str) -> str:
    """Best-effort severity label from an embedded CVSS vector string.

    Parses the vector into metric=value pairs (so ``AC:H`` is not mistaken for
    a confidentiality-high ``C:H``) and applies a coarse, descriptive band.
    """
    v = (cvss_vector or "").upper()
    if not v:
        return "unknown"
    metrics: dict[str, str] = {}
    for part in v.split("/"):
        if ":" in part:
            k, _, val = part.partition(":")
            metrics[k] = val
    # CVSS v3: C/I/A   ·   CVSS v4: VC/VI/VA
    high_impact = any(metrics.get(k) == "H" for k in ("C", "I", "A", "VC", "VI", "VA"))
    net = metrics.get("AV") == "N"
    low_priv = metrics.get("PR") == "N"
    if high_impact and net and low_priv:
        return "critical"
    if high_impact and net:
        return "high"
    if high_impact:
        return "medium"
    return "low"


def count() -> int:
    return VulnDB().count()
