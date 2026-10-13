"""Audit of IOC extraction on the AnnoCTR test reports.

None of the datasets annotates indicators, so precision and recall are estimated from a
labelled sample of the 34 AnnoCTR test reports (real vendor reports). The published labels
come from a single annotator, an AI agent that read each value in its context
(``gleaner audit-sample`` writes that context to ``runtime/``, which is not committed):

* ``exported``    up to 40 exported values per type -> precision per type
* ``withheld``    values found but not exported (references, benign, internal) -> missed IOCs
* ``missed``      values matched by deliberately loose patterns but not extracted at all
                  (``cmd.exe``, ``System.Net``, partial addresses...) -> missed IOCs

Labels: ``ioc`` (indicator of the reported activity), ``benign`` (a valid observable that is
not an indicator: citation, legitimate service, generic system path), ``invalid`` (an
extraction error: truncated, glued or mistyped value) and, in the two missed pools, ``scope``
(an indicator of a type Gleaner does not extract: a bare file name such as ``pin.vbs``).
``reports/ioc_audit.csv`` stores labels against a hash of each value, never the value
itself, so the published file contains no indicator or corpus text.
"""

from __future__ import annotations

import csv
import hashlib
import random
import re
from collections import Counter, defaultdict
from pathlib import Path

from gleaner import datasets
from gleaner.iocs import (
    EXPORTED_STATUSES,
    HASH_TYPES,
    HOST_TYPES,
    IOC_TYPES,
    NETWORK_TYPES,
    extract_iocs,
    refang,
)
from gleaner.metrics import wilson

PER_TYPE = 40
WITHHELD = 60
MISSED = 80
_LOOSE = {
    "url": r"\b(?:https?|ftp)://\S+",
    "domain-name": r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b",
    "ipv4-addr": r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
    "hash": r"\b[0-9A-Fa-f]{32,}\b",
    "cve": r"\bCVE-\d{4}-\d+\b",
    "file-path": r"(?:\b[A-Za-z]:|%\w+%)\\\S+",
    "registry-key": r"\bHK(?:LM|CU|CR|U|CC|EY_\w+)\\\S+",
}


def value_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def loose_candidates(text: str) -> set[tuple[str, str]]:
    """High-recall, low-precision matches: (kind, value)."""
    clean = refang(text).text
    found = set()
    for kind, pattern in _LOOSE.items():
        for m in re.finditer(pattern, clean):
            found.add((kind, m.group().rstrip(".,;:)]*'\"")))
    return found


def _rows(raw: Path) -> list[dict]:
    """Every audit candidate on the test split, with its part and context."""
    rows = []
    for doc, text in sorted(datasets.annoctr_texts("test", raw).items()):
        iocs = extract_iocs(text)
        values = {i.value.lower() for i in iocs}
        for ioc in iocs:
            part = "exported" if ioc.status in EXPORTED_STATUSES else "withheld"
            rows.append(_row(part, doc, ioc.type, ioc.status, ioc.value, text, ioc.offsets[0]))
        clean = refang(text).text
        for kind, value in sorted(loose_candidates(text)):
            low = value.lower()
            if any(low in v or v in low for v in values):
                continue
            rows.append(_row("missed", doc, kind, "-", value, clean, max(clean.find(value), 0)))
    return rows


def _row(part: str, doc: str, kind: str, status: str, value: str, text: str, offset: int) -> dict:
    context = text[max(0, offset - 160) : offset + len(value) + 100].replace("\n", " ⏎ ")
    return {
        "part": part,
        "doc": doc,
        "type": kind,
        "status": status,
        "value_key": value_key(value),
        "value": value,
        "context": context,
    }


def sample(rows: list[dict], seed: int = 0) -> list[dict]:
    rng = random.Random(seed)
    chosen = []
    by_type: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        if r["part"] == "exported":
            by_type[r["type"]].append(r)
    for kind in sorted(by_type):
        chosen += rng.sample(by_type[kind], min(PER_TYPE, len(by_type[kind])))
    for part, n in (("withheld", WITHHELD), ("missed", MISSED)):
        pool = [r for r in rows if r["part"] == part]
        chosen += rng.sample(pool, min(n, len(pool)))
    return chosen


def write_sample(raw: Path, out: Path, seed: int = 0) -> int:
    rows = sample(_rows(raw), seed)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=[*rows[0].keys(), "label"])
        writer.writeheader()
        for r in rows:
            writer.writerow({**r, "label": ""})
    return len(rows)


def read_labels(path: Path) -> dict[tuple[str, str, str, str], str]:
    with path.open(encoding="utf-8") as fh:
        return {
            (r["part"], r["doc"], r["type"], r["value_key"]): r["label"] for r in csv.DictReader(fh)
        }


def score(raw: Path, labels_path: Path) -> dict:
    """Precision per type, and recall estimated against the withheld and loose pools."""
    rows = _rows(raw)
    labels = read_labels(labels_path)
    population = Counter((r["part"], r["type"] if r["part"] == "exported" else "*") for r in rows)
    labelled: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for r in rows:
        label = labels.get((r["part"], r["doc"], r["type"], r["value_key"]))
        if label:
            labelled[r["part"], r["type"] if r["part"] == "exported" else "*"][label] += 1

    per_type = {}
    est_tp = 0.0
    for kind in IOC_TYPES:
        n_pop = population.get(("exported", kind), 0)
        counts = labelled.get(("exported", kind), Counter())
        n = sum(counts.values())
        if not n_pop:
            continue
        precision = counts["ioc"] / n if n else 0.0
        lo, hi = wilson(counts["ioc"], n)
        est_tp += precision * n_pop
        per_type[kind] = {
            "extracted": n_pop,
            "audited": n,
            "ioc": counts["ioc"],
            "benign": counts["benign"],
            "invalid": counts["invalid"],
            "precision": precision,
            "precision_ci95": [lo, hi],
            "valid_observable_rate": (counts["ioc"] + counts["benign"]) / n if n else 0.0,
        }
    exported = sum(v["extracted"] for v in per_type.values())
    groups = {
        "network_and_hashes": [*NETWORK_TYPES, *HASH_TYPES],
        "host_artifacts": list(HOST_TYPES),
    }
    by_group = {}
    for name, kinds in groups.items():
        present = [per_type[k] for k in kinds if k in per_type]
        n_pop = sum(v["extracted"] for v in present)
        tp = sum(v["precision"] * v["extracted"] for v in present)
        by_group[name] = {"extracted": n_pop, "precision": tp / n_pop if n_pop else 0.0}
    missed = {}
    est_fn = 0.0
    for part in ("withheld", "missed"):
        n_pop = population.get((part, "*"), 0)
        counts = labelled.get((part, "*"), Counter())
        n = sum(counts.values())
        rate = counts["ioc"] / n if n else 0.0
        est_fn += rate * n_pop
        missed[part] = {
            "population": n_pop,
            "audited": n,
            "ioc": counts["ioc"],
            "out_of_scope": counts["scope"],
            "ioc_rate": rate,
        }
    return {
        "documents": len({r["doc"] for r in rows}),
        "exported": exported,
        "per_type": per_type,
        "precision": est_tp / exported if exported else 0.0,
        "by_group": by_group,
        "missed_pools": missed,
        "estimated_true_positives": est_tp,
        "estimated_false_negatives": est_fn,
        "recall": est_tp / (est_tp + est_fn) if est_tp + est_fn else 0.0,
        "labels": sum(sum(c.values()) for c in labelled.values()),
    }
