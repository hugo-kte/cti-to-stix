"""Markdown summary of an extraction (indicators are shown defanged)."""

from __future__ import annotations

from collections import Counter

from gleaner import __version__
from gleaner.attack import Catalog
from gleaner.iocs import IOC_TYPES, defang
from gleaner.pipeline import Extraction

_STATUS_ORDER = ("indicator", "artifact", "vulnerability")


def _cell(text: str, limit: int = 140) -> str:
    text = " ".join(text.split()).replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def markdown(extraction: Extraction, catalog: Catalog) -> str:
    lines = [f"# {extraction.title}", ""]
    source = f"`{extraction.source}` · " if extraction.source else ""
    lines += [
        f"_{source}sha256 `{extraction.sha256[:12]}…` · {len(extraction.sentences)} sentences · "
        f"Gleaner {__version__} ({', '.join(extraction.components)})_",
        "",
    ]

    exported = [i for i in extraction.iocs if i.status in _STATUS_ORDER]
    exported.sort(key=lambda i: (_STATUS_ORDER.index(i.status), IOC_TYPES.index(i.type), i.value))
    lines += [f"## Indicators ({len(exported)})", ""]
    if exported:
        lines += ["| Type | Value | Exported as | Mentions |", "|---|---|---|---:|"]
        for ioc in exported:
            shown = defang(ioc.value) if ioc.status == "indicator" else ioc.value
            note = " (documentation range)" if ioc.scope == "documentation" else ""
            lines.append(
                f"| {ioc.type} | `{_cell(shown, 90)}` | {ioc.status}{note} | {ioc.count} |"
            )
    skipped = Counter(i.status for i in extraction.iocs if i.status not in _STATUS_ORDER)
    if skipped:
        parts = ", ".join(f"{n} {status}" for status, n in sorted(skipped.items()))
        lines += ["", f"Not exported: {parts} (references, well-known services, non-routable)."]
    lines.append("")

    lines += [f"## Named entities ({len(extraction.entities)})", ""]
    if extraction.entities:
        lines += ["| Type | Name | ATT&CK | Mentions | Found by |", "|---|---|---|---:|---|"]
        for e in extraction.entities:
            obj = catalog.get(e.attack_id) if e.attack_id else None
            link = f"[{obj.attack_id}]({obj.url})" if obj else "–"
            found_by = ", ".join(e.sources)
            name = _cell(e.name, 60)
            lines.append(f"| {e.label.lower()} | {name} | {link} | {e.mentions} | {found_by} |")
    lines.append("")

    lines += [f"## ATT&CK techniques ({len(extraction.techniques)})", ""]
    if extraction.techniques:
        lines += ["| Technique | Tactics | Score | Found by | Evidence |", "|---|---|---:|---|---|"]
        for t in extraction.techniques:
            obj = catalog.get(t.attack_id)
            name = f"[{t.attack_id}]({obj.url}) {t.name}" if obj else f"{t.attack_id} {t.name}"
            lines.append(
                f"| {name} | {', '.join(t.tactics)} | {t.score:.2f} | {', '.join(t.sources)} | "
                f"{_cell(t.evidence, 110)} |"
            )
    lines.append("")
    return "\n".join(lines)
