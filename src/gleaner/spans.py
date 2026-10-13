"""Entity mentions as token spans, and BIO conversions."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Mention:
    """An entity mention over tokens ``[start, end)`` of one sentence."""

    start: int
    end: int
    label: str  # GROUP | MALWARE | TOOL | TECHNIQUE | TACTIC | ORG | LOC | ...
    attack_id: str | None = None
    source: str = ""  # gazetteer | crf

    @property
    def key(self) -> tuple[int, int, str]:
        return (self.start, self.end, self.label)

    def overlaps(self, other: Mention) -> bool:
        return self.start < other.end and other.start < self.end


def bio_to_spans(tags: Sequence[str]) -> set[tuple[int, int, str]]:
    """BIO tags -> ``{(start, end, label)}``. A stray ``I-`` opens a new span (conlleval)."""
    spans = set()
    start, label = None, None
    for i, tag in enumerate([*tags, "O"]):
        prefix, _, kind = tag.partition("-")
        if start is not None and (prefix in ("O", "B") or kind != label):
            spans.add((start, i, label))
            start, label = None, None
        if prefix == "B" or (prefix == "I" and start is None):
            start, label = i, kind
    return spans


def spans_to_bio(length: int, spans: Iterable[tuple[int, int, str]]) -> list[str]:
    tags = ["O"] * length
    for start, end, label in sorted(spans):
        if any(t != "O" for t in tags[start:end]):
            continue  # first span wins on overlap
        tags[start] = f"B-{label}"
        for i in range(start + 1, end):
            tags[i] = f"I-{label}"
    return tags


def merge(primary: Sequence[Mention], secondary: Sequence[Mention]) -> list[Mention]:
    """``primary`` mentions plus every ``secondary`` one that overlaps none of them."""
    out = list(primary)
    for m in secondary:
        if not any(m.overlaps(p) for p in primary):
            out.append(m)
    return sorted(out, key=lambda m: m.start)
