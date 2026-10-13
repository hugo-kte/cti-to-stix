"""Precision/recall/F1 for spans and multi-label predictions, and binomial intervals."""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable, Sequence

import numpy as np

Span = tuple[int, int, str]
THRESHOLDS = (0.02, 0.03, 0.05, 0.07, *(round(0.1 + 0.05 * i, 2) for i in range(13)))  # ... 0.7


def prf(tp: int, fp: int, fn: int, found: int | None = None) -> dict[str, float | int]:
    """P/R/F1. ``found`` is the number of gold items matched when it differs from ``tp``, the
    number of correct predictions (lenient span matching: one prediction may overlap two gold
    spans, or two predictions one)."""
    found = tp if found is None else found
    p = tp / (tp + fp) if tp + fp else 0.0
    r = found / (found + fn) if found + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {
        "precision": p,
        "recall": r,
        "f1": f,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "support": found + fn,
    }


def span_scores(
    gold: Sequence[set[Span]],
    pred: Sequence[set[Span]],
    labels: Iterable[str],
    lenient: bool = False,
) -> dict:
    """Entity-level scores.

    Strict: a prediction is correct if a gold span has the same boundaries and label. Lenient:
    a prediction is correct if it overlaps a gold span of the same label (precision), and a gold
    span is found if a prediction of its label overlaps it (recall).
    """
    labels = list(labels)
    tp: Counter[str] = Counter()
    fp: Counter[str] = Counter()
    fn: Counter[str] = Counter()
    found: Counter[str] = Counter()  # lenient only: gold spans overlapped by a prediction
    for g_all, p_all in zip(gold, pred, strict=True):
        g = {s for s in g_all if s[2] in labels}
        p = {s for s in p_all if s[2] in labels}
        if lenient:
            for s in p:
                (tp if any(_overlap(s, t) for t in g) else fp)[s[2]] += 1
            for s in g:
                (found if any(_overlap(s, t) for t in p) else fn)[s[2]] += 1
        else:
            for s in p:
                (tp if s in g else fp)[s[2]] += 1
            for s in g - p:
                fn[s[2]] += 1
    matched = found if lenient else tp  # gold spans found (strict: one per correct prediction)
    per_label = {lab: prf(tp[lab], fp[lab], fn[lab], matched[lab]) for lab in labels}
    micro = prf(*(sum(counts[lab] for lab in labels) for counts in (tp, fp, fn, matched)))
    macro_f1 = float(np.mean([per_label[lab]["f1"] for lab in labels])) if labels else 0.0
    return {"per_label": per_label, "micro": micro, "macro_f1": macro_f1}


def _overlap(a: Span, b: Span) -> bool:
    return a[2] == b[2] and a[0] < b[1] and b[0] < a[1]


def multilabel_scores(y_true: np.ndarray, y_pred: np.ndarray, labels: Sequence[str]) -> dict:
    """Micro and macro P/R/F1 over labels, plus per-label scores."""
    y_true = np.asarray(y_true, dtype=bool)
    y_pred = np.asarray(y_pred, dtype=bool)
    tp = (y_true & y_pred).sum(axis=0)
    fp = (~y_true & y_pred).sum(axis=0)
    fn = (y_true & ~y_pred).sum(axis=0)
    per_label = {lab: prf(int(tp[j]), int(fp[j]), int(fn[j])) for j, lab in enumerate(labels)}
    micro = prf(int(tp.sum()), int(fp.sum()), int(fn.sum()))
    present = [lab for lab in labels if per_label[lab]["support"]]
    macro = {
        k: float(np.mean([per_label[lab][k] for lab in present])) if present else 0.0
        for k in ("precision", "recall", "f1")
    }
    return {"micro": micro, "macro": macro, "per_label": per_label}


def best_threshold(
    y_true: np.ndarray, proba: np.ndarray, grid: Iterable[float] = THRESHOLDS
) -> tuple[float, float]:
    """Global probability threshold maximising micro-F1: (threshold, micro-F1)."""
    best = (0.5, -1.0)
    for t in grid:
        f1 = multilabel_scores(y_true, proba >= t, range(y_true.shape[1]))["micro"]["f1"]
        if f1 > best[1]:
            best = (float(t), f1)
    return best


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95 % Wilson score interval for a proportion k/n."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (max(0.0, centre - half), min(1.0, centre + half))
