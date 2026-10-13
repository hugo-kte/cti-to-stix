"""Report figures (matplotlib, Agg), same visual spec as the rest of the portfolio."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import PercentFormatter

SURFACE, INK, INK2, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
ENTITY_SYSTEMS = {
    "gazetteer, names only": "Gazetteer, ATT&CK names only",
    "gazetteer + rules": "Gazetteer + learned rules",
    "CRF": "CRF",
    "CRF + gazetteer features": "CRF + gazetteer features",
    "CRF + gazetteer features ∪ gazetteer": "CRF + gazetteer features ∪ gazetteer",
}
ENTITY_LABELS = {
    "GROUP": "Group",
    "MALWARE": "Malware",
    "TOOL": "Tool",
    "TECHNIQUE": "Technique\n(explicit)",
    "TACTIC": "Tactic",
}
IOC_NAMES = {
    "url": "URL",
    "domain-name": "Domain",
    "ipv4-addr": "IPv4",
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "file-path": "File path",
    "registry-key": "Registry key",
    "cve": "CVE",
}

plt.rcParams.update(
    {
        "font.family": ["Helvetica Neue", "Helvetica", "Arial", "DejaVu Sans"],
        "font.size": 10,
        "axes.labelcolor": INK2,
        "text.color": INK,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
        "xtick.labelcolor": INK2,
        "ytick.labelcolor": INK2,
        "legend.frameon": False,
        "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
    }
)


def _style(ax: plt.Axes) -> None:
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.tick_params(length=0)
    ax.grid(color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def _label(ax: plt.Axes, text: str, offset: float, **style: Any) -> None:
    """Left-aligned text ``offset`` points above the axes."""
    ax.annotate(
        text,
        xy=(0, 1),
        xycoords="axes fraction",
        xytext=(0, offset),
        textcoords="offset points",
        va="bottom",
        **style,
    )


def _titles(ax: plt.Axes, title: str, subtitle: str, offset: float = 8) -> None:
    _label(ax, subtitle, offset, fontsize=9.5, color=INK2)
    _label(ax, title, offset + 18, fontsize=13, fontweight="bold", color=INK)


def _save(fig: plt.Figure, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=200, bbox_inches="tight", pad_inches=0.25)
    plt.close(fig)
    return path


def ioc_precision(metrics: dict[str, Any], path: Path) -> Path:
    """Audited precision per indicator type, with 95 % Wilson intervals."""
    audit = metrics["iocs"]["audit"]
    rows = [(k, v) for k, v in audit["per_type"].items() if v["audited"] >= 5]
    rows.sort(key=lambda kv: kv[1]["precision"])
    fig, ax = plt.subplots(figsize=(7.6, 0.42 * len(rows) + 1.4), dpi=100)
    _style(ax)
    ax.grid(axis="y", visible=False)
    ys = np.arange(len(rows))
    prec = np.array([v["precision"] for _, v in rows])
    lo = np.array([v["precision_ci95"][0] for _, v in rows])
    hi = np.array([v["precision_ci95"][1] for _, v in rows])
    colors = [SERIES[1] if k in ("file-path", "registry-key") else SERIES[0] for k, _ in rows]
    ax.barh(ys, prec, 0.62, color=colors, lw=0)
    ax.errorbar(
        prec, ys, xerr=[prec - lo, hi - prec], fmt="none", ecolor=INK, elinewidth=1, capsize=3
    )
    for y, (_, v) in zip(ys, rows, strict=True):
        ax.text(1.02, y, f"{v['ioc']}/{v['audited']}", va="center", fontsize=8.5, color=INK2)
    ax.set_yticks(ys, [IOC_NAMES.get(k, k) for k, _ in rows])
    ax.set_xlim(0, 1.0)
    ax.xaxis.set_major_formatter(PercentFormatter(1.0))
    ax.set_xlabel("Share of audited extractions that are indicators of the reported activity")
    _titles(
        ax,
        "IOC precision on real threat reports",
        f"{sum(v['audited'] for _, v in rows)} audited exports from {audit['documents']} AnnoCTR "
        "test reports; whiskers: 95% CI; orange: host artifacts",
    )
    return _save(fig, path)


def entity_f1(metrics: dict[str, Any], path: Path) -> Path:
    """Strict entity-level F1 per type for the gazetteer, the CRF and their combinations."""
    systems = metrics["entities"]["systems"]
    labels = list(ENTITY_LABELS)
    names = [s for s in ENTITY_SYSTEMS if s in systems]
    fig, ax = plt.subplots(figsize=(7.6, 4.4), dpi=100)
    _style(ax)
    ax.grid(axis="x", visible=False)
    width, gap = 0.15, 0.01
    offset = (len(names) - 1) / 2
    for k, name in enumerate(names):
        f1 = [systems[name]["strict"]["per_label"][lab]["f1"] for lab in labels]
        xs = np.arange(len(labels)) + (k - offset) * (width + gap)
        ax.bar(xs, f1, width, color=SERIES[k % len(SERIES)], lw=0, label=ENTITY_SYSTEMS[name])
    ax.set_xticks(np.arange(len(labels)), [ENTITY_LABELS[lab] for lab in labels])
    ax.set_ylim(0, 1.0)
    ax.set_ylabel("F1 (exact span and type)")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.2), ncol=2, fontsize=9, labelcolor=INK2)
    support = metrics["entities"]["support"]
    _titles(
        ax,
        "Named entities: dictionary vs. learned tagger",
        f"AnnoCTR test split, {metrics['entities']['documents']} reports; gold mentions: "
        + ", ".join(
            f"{ENTITY_LABELS[lab].split(chr(10))[0].lower()} {support.get(lab, 0)}"
            for lab in labels
        ),
    )
    return _save(fig, path)


def technique_protocols(metrics: dict[str, Any], path: Path) -> Path:
    """Micro and macro F1 of the technique classifier under different evaluation protocols."""
    t = metrics["techniques"]
    bars = [
        ("ATT&CK name\nmatching", t["name_matching_baseline"]),
        ("Random\nsentence split", t["protocols"]["random_sentence_split"]),
        ("Document-grouped\nsplit", t["protocols"]["document_grouped_split"]),
        ("Grouped + near-dup.\nfiltered, nested", t["nested_cv"]),
    ]
    fig, ax = plt.subplots(figsize=(7.6, 4.2), dpi=100)
    _style(ax)
    ax.grid(axis="x", visible=False)
    xs = np.arange(len(bars))
    width = 0.34
    for k, (metric, color, name) in enumerate(
        (("micro", SERIES[0], "Micro-F1"), ("macro", SERIES[1], "Macro-F1"))
    ):
        values = [b[metric]["f1"] for _, b in bars]
        pos = xs + (k - 0.5) * (width + 0.02)
        ax.bar(pos, values, width, color=color, lw=0, label=name)
        for x, v in zip(pos, values, strict=True):
            ax.text(x, v + 0.012, f"{v:.2f}", ha="center", fontsize=8.5, color=INK2)
    ax.set_xticks(xs, [name for name, _ in bars])
    ax.set_ylim(0, 1.0)
    ax.set_ylabel("F1 over 50 techniques")
    ax.legend(loc="upper left", fontsize=9, labelcolor=INK2)
    d = t["dataset"]
    _titles(
        ax,
        "How the split changes the score",
        f"TRAM: {d['sentences']:,} sentences ({d['labelled_sentences']:,} labelled) from "
        f"{d['documents']} reports; same model, 5-fold cross-validation",
    )
    return _save(fig, path)


def technique_long_tail(metrics: dict[str, Any], path: Path) -> Path:
    """Per-technique F1 against the number of labelled sentences."""
    per = metrics["techniques"]["per_technique"]
    ids = list(per)
    n = np.array([per[i]["sentences"] for i in ids])
    f1 = np.array([per[i]["f1"] for i in ids])
    fig, ax = plt.subplots(figsize=(7.6, 4.4), dpi=100)
    _style(ax)
    ax.scatter(n, f1, s=34, color=SERIES[0], ec=SURFACE, lw=1.0, zorder=3)
    ax.set_xscale("log")
    ax.set_ylim(-0.03, 1.0)
    ax.set_xlabel("Labelled sentences in TRAM (log scale)")
    ax.set_ylabel("F1, nested cross-validation")
    order = np.argsort(n, kind="stable")
    rare, frequent = list(order[:3]), list(order[-3:])
    zero = [j for j in rare if f1[j] == 0]
    if zero:  # several rare techniques sit at F1 = 0: one label for all of them
        ax.annotate(
            "F1 = 0: " + ", ".join(ids[j] for j in zero),
            (n[zero[0]], 0.0),
            xytext=(0, 9),
            textcoords="offset points",
            fontsize=7.5,
            color=INK2,
        )
    for j in [*(j for j in rare if j not in zero), *frequent]:
        name = per[ids[j]]["name"]
        name = name if len(name) <= 26 else name[:25].rsplit(" ", 1)[0] + "…"
        right_side = n[j] > np.median(n)
        ax.annotate(
            f"{ids[j]} {name}",
            (n[j], f1[j]),
            xytext=(-6 if right_side else 6, 4),
            textcoords="offset points",
            ha="right" if right_side else "left",
            fontsize=7.5,
            color=INK2,
        )
    rho = np.corrcoef(np.log(n), f1)[0, 1]
    _titles(
        ax,
        "The long tail: rare techniques are rarely found",
        f"{len(ids)} techniques; correlation of F1 with log(sentences): {rho:.2f}",
    )
    return _save(fig, path)


def cross_dataset(metrics: dict[str, Any], path: Path) -> Path:
    """Top-1 accuracy in domain (TRAM) and on AnnoCTR technique mentions."""
    c = metrics["cross"]
    bars = [
        (
            "TRAM sentences\n(nested CV)",
            metrics["techniques"]["nested_cv"]["top1_accuracy_labelled"],
        ),
        ("AnnoCTR\nexplicit mentions", c["explicit"]["top1"]),
        ("AnnoCTR\nimplicit mentions", c["implicit"]["top1"]),
    ]
    fig, ax = plt.subplots(figsize=(7.6, 4.0), dpi=100)
    _style(ax)
    ax.grid(axis="x", visible=False)
    xs = np.arange(len(bars))
    values = [v for _, v in bars]
    ax.bar(xs, values, 0.55, color=[SERIES[0], SERIES[1], SERIES[1]], lw=0)
    for x, v in zip(xs, values, strict=True):
        ax.text(x, v + 0.015, f"{v:.0%}", ha="center", fontsize=9, color=INK2)
    ax.set_xticks(xs, [name for name, _ in bars])
    ax.set_ylim(0, 1.0)
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax.set_ylabel("Top-1 technique correct")
    _titles(
        ax,
        "Domain shift: TRAM model on AnnoCTR",
        f"Only {c['all']['in_scope_share']:.0%} of AnnoCTR's {c['all']['mentions']:,} technique "
        "mentions use one of TRAM's 50 techniques; scored on those",
    )
    return _save(fig, path)


def all_figures(metrics: dict[str, Any], out_dir: Path) -> list[Path]:
    makers = {
        "ioc_precision.png": ("iocs", ioc_precision),
        "entity_f1.png": ("entities", entity_f1),
        "technique_protocols.png": ("techniques", technique_protocols),
        "technique_long_tail.png": ("techniques", technique_long_tail),
        "cross_dataset.png": ("cross", cross_dataset),
    }
    paths = []
    for name, (section, make) in makers.items():
        if section in metrics and (section != "iocs" or "audit" in metrics["iocs"]):
            if section == "cross" and "techniques" not in metrics:
                continue
            paths.append(make(metrics, out_dir / name))
    return paths
