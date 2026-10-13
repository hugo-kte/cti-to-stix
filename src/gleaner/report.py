"""REPORT.md: every table rendered from reports/metrics.json."""

from __future__ import annotations

from typing import Any

from gleaner.plots import ENTITY_LABELS, IOC_NAMES

ENTITY_ORDER = (
    "gazetteer, names only",
    "gazetteer + rules",
    "CRF",
    "CRF + gazetteer features",
    "CRF ∪ gazetteer",
    "CRF + gazetteer features ∪ gazetteer",
)


def _pct(x: float) -> str:
    return f"{x:.1%}"


def _f(x: float) -> str:
    return f"{x:.3f}"


def _row(*cells: object) -> str:
    return "| " + " | ".join(str(c) for c in cells) + " |"


def _iocs(m: dict[str, Any]) -> list[str]:
    i = m["iocs"]
    out = [
        "## Indicators of compromise",
        "",
        f"Extraction over the {i['documents']} AnnoCTR test reports "
        f"({i['documents_with_defanged_indicators']} of them defang at least one indicator).",
        "",
        "| Status | Values |",
        "|---|---:|",
        *[f"| {k} | {v} |" for k, v in i["by_status"].items()],
        "",
    ]
    if "audit" not in i:
        return out
    a = i["audit"]
    out += [
        f"### Audit ({a['labels']} labels, one annotator: an AI agent)",
        "",
        "| Type | Exported | Audited | IOC | Benign | Invalid | Precision | 95% CI |",
        "|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    for kind, v in a["per_type"].items():
        lo, hi = v["precision_ci95"]
        out.append(
            f"| {IOC_NAMES.get(kind, kind)} | {v['extracted']} | {v['audited']} | {v['ioc']} | "
            f"{v['benign']} | {v['invalid']} | {_pct(v['precision'])} | {_pct(lo)}–{_pct(hi)} |"
        )
    g = a["by_group"]
    w, mp = a["missed_pools"]["withheld"], a["missed_pools"]["missed"]
    out += [
        "",
        f"* Precision, stratified by type: **{_pct(a['precision'])}** overall; network indicators "
        f"and digests {_pct(g['network_and_hashes']['precision'])}, host artifacts "
        f"{_pct(g['host_artifacts']['precision'])}.",
        f"* Withheld values (references, benign, internal): {w['ioc']}/{w['audited']} audited were "
        f"missed indicators (population {w['population']}).",
        f"* Loose-pattern candidates not extracted: {mp['ioc']}/{mp['audited']} were missed "
        f"in-scope indicators, {mp['out_of_scope']} were bare file names (out of scope) "
        f"(population {mp['population']}).",
        f"* Estimated recall against these pools: **{_pct(a['recall'])}**.",
        "",
        "![IOC precision](figures/ioc_precision.png)",
        "",
    ]
    return out


def _entities(m: dict[str, Any]) -> list[str]:
    e = m["entities"]
    labels = list(ENTITY_LABELS)
    head = " | ".join(ENTITY_LABELS[lab].replace("\n", " ") for lab in labels)
    out = [
        "## Named entities (AnnoCTR test split)",
        "",
        f"{e['documents']} reports, {e['sentences']:,} sentences. Strict entity-level F1 "
        "(exact boundaries and type); micro-averaged over the five types.",
        "",
        f"| System | {head} | Micro P | Micro R | Micro F1 | Lenient micro F1 |",
        "|---|" + "---:|" * (len(labels) + 4),
    ]
    for name in ENTITY_ORDER:
        if name not in e["systems"]:
            continue
        s = e["systems"][name]
        cells = " | ".join(_f(s["strict"]["per_label"][lab]["f1"]) for lab in labels)
        mi = s["strict"]["micro"]
        out.append(
            f"| {name} | {cells} | {_f(mi['precision'])} | {_f(mi['recall'])} | "
            f"**{_f(mi['f1'])}** | {_f(s['lenient']['micro']['f1'])} |"
        )
    out += [
        "",
        "Gold support: " + ", ".join(f"{k} {v}" for k, v in e["support"].items()),
        "",
        "![Entity F1](figures/entity_f1.png)",
        "",
    ]
    crf = e["systems"].get("CRF + gazetteer features", {}).get("all_labels")
    if crf:
        out += [
            "CRF + gazetteer features on every AnnoCTR type:",
            "",
            "| Type | P | R | F1 | Support |",
            "|---|---:|---:|---:|---:|",
        ]
        for lab, v in sorted(crf["per_label"].items(), key=lambda kv: -kv[1]["support"]):
            out.append(_row(lab, _f(v["precision"]), _f(v["recall"]), _f(v["f1"]), v["support"]))
        out.append("")
    out += [
        "### ATT&CK coverage and alias linking",
        "",
        _row(
            "Type",
            "Gold mentions",
            "Linked to ATT&CK by annotators",
            "Linked correctly by the gazetteer",
            "Linked although annotators chose another entry",
        ),
        "|---|---:|---:|---:|---:|",
    ]
    for lab, v in e["linking"].items():
        out.append(
            f"| {lab} | {v['mentions']} | {v['in_attack']} ({_pct(v['in_attack_share'])}) | "
            f"{v['correct']}/{v['in_attack']} ({_pct(v['accuracy'])}) | "
            f"{v['extra_links']}/{v['outside_attack']} |"
        )
    return [*out, ""]


def _techniques(m: dict[str, Any]) -> list[str]:
    t = m["techniques"]
    d, n = t["dataset"], t["nested_cv"]
    p = t["protocols"]
    out = [
        "## ATT&CK technique classification (TRAM)",
        "",
        f"{d['sentences']:,} sentences ({d['labelled_sentences']:,} labelled with at least one of "
        f"{d['techniques']} techniques) from {d['documents']} reports, merged into "
        f"{d['document_groups']} document groups. {d['near_duplicates_dropped']} test sentences "
        "with a near-duplicate in their training folds were not scored.",
        "",
        "| Protocol | Micro P | Micro R | Micro F1 | Macro F1 |",
        "|---|---:|---:|---:|---:|",
    ]
    rows = [
        ("ATT&CK name matching (no training)", t["name_matching_baseline"]),
        ("Random sentence split (leaky)", p["random_sentence_split"]),
        ("Document-grouped split", p["document_grouped_split"]),
        ("Document-grouped, near-duplicates filtered, nested selection", n),
    ]
    for name, r in rows:
        mi = r["micro"]
        out.append(
            _row(name, _f(mi["precision"]), _f(mi["recall"]), _f(mi["f1"]), _f(r["macro"]["f1"]))
        )
    cfg = p["fixed_config"]
    out += [
        "",
        f"Fixed model for the protocol comparison: {cfg['features']} TF-IDF, C={cfg['C']}, "
        f"class_weight={cfg['class_weight']}, threshold {cfg['threshold']}. Nested CV fold std: "
        f"micro-F1 ±{n['fold_micro_f1_std']:.3f}, macro-F1 ±{n['fold_macro_f1_std']:.3f}. "
        f"Top-1 accuracy on labelled sentences: {_pct(n['top1_accuracy_labelled'])}.",
        "",
        _row(
            "Fold",
            "Selected features",
            "C",
            "class_weight",
            "Threshold",
            "Test docs",
            "Dropped near-dups",
            "Micro F1",
            "Macro F1",
        ),
        "|---:|---|---:|---|---:|---:|---:|---:|---:|",
    ]
    for f in n["folds"]:
        c = f["config"]
        out.append(
            _row(
                f["fold"],
                c["features"],
                c["C"],
                c["class_weight"],
                f["threshold"],
                f["test_documents"],
                f["near_duplicates_dropped"],
                _f(f["micro_f1"]),
                _f(f["macro_f1"]),
            )
        )
    out += [
        "",
        "![Protocols](figures/technique_protocols.png)",
        "",
        "![Long tail](figures/technique_long_tail.png)",
        "",
        "### Per technique (nested CV)",
        "",
        "| Technique | Name | Sentences | P | R | F1 |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for tid, v in sorted(t["per_technique"].items(), key=lambda kv: -kv[1]["sentences"]):
        current = f" → {v['current_id']}" if v.get("current_id") and v["current_id"] != tid else ""
        out.append(
            f"| {tid}{current} | {v['name']} | {v['sentences']} | {_f(v['precision'])} | "
            f"{_f(v['recall'])} | {_f(v['f1'])} |"
        )
    return [*out, ""]


def _cross(m: dict[str, Any]) -> list[str]:
    c = m["cross"]
    out = [
        "## Cross-dataset check: TRAM model on AnnoCTR technique mentions",
        "",
        f"{c['all']['mentions']:,} AnnoCTR mentions linked to an ATT&CK technique "
        f"({c['distinct_gold_techniques']} distinct techniques, "
        f"{c['distinct_gold_in_scope']} of them among TRAM's 50). "
        "The classifier sees the mention's sentence.",
        "",
        _row(
            "Mentions",
            "Count",
            "In TRAM's label set",
            "Top-1",
            "Top-3",
            "Above threshold",
            "Parent technique top-1",
        ),
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name in ("all", "explicit", "implicit"):
        v = c[name]
        out.append(
            _row(
                name,
                v["mentions"],
                f"{v['in_scope']} ({_pct(v['in_scope_share'])})",
                _pct(v["top1"]),
                _pct(v["top3"]),
                _pct(v["recall_at_threshold"]),
                _pct(v["parent_top1"]),
            )
        )
    return [*out, "", "![Cross-dataset](figures/cross_dataset.png)", ""]


def _stix(m: dict[str, Any]) -> list[str]:
    s = m["stix"]
    objects = ", ".join(f"{k} {v:.1f}" for k, v in s["objects_per_report"].items())
    return [
        "## STIX 2.1 export, end to end",
        "",
        f"{s['valid_bundles']}/{s['reports']} bundles valid under `stix2-validator` strict mode "
        f"({s['validator_errors']} errors, {s['validator_warnings']} warnings); "
        f"{s['seconds_per_report']:.2f} s per report with {', '.join(s['components'])}.",
        "",
        f"Objects per report: {objects}.",
        "",
    ]


def render(m: dict[str, Any]) -> str:
    meta = m.get("meta", {})
    lines = [
        "# Gleaner evaluation report",
        "",
        f"_Generated {meta.get('generated', '?')} with Gleaner {meta.get('gleaner_version', '?')}, "
        f"MITRE ATT&CK {meta.get('attack_version', '?')}. All numbers come from `metrics.json`._",
        "",
    ]
    for key, section in (
        ("iocs", _iocs),
        ("entities", _entities),
        ("techniques", _techniques),
        ("cross", _cross),
        ("stix", _stix),
    ):
        if key in m:
            lines += section(m)
    if "training" in m and "ner" in m["training"]:
        ner = m["training"]["ner"]
        kept = {(b["variant"], b["c1"], b["c2"]) for b in ner.get("best", {}).values()}
        lines += [
            "## Model selection (AnnoCTR dev)",
            "",
            "Each variant keeps the `c1`/`c2` pair with the best dev micro-F1 over all AnnoCTR "
            "types (✓); the pipeline uses the variant whose kept pair scores higher on the five "
            "CTI types. Both final taggers are then refit on train+dev.",
            "",
            "| Variant | c1 | c2 | Dev micro F1, all types | Dev micro F1, CTI types | Kept |",
            "|---|---:|---:|---:|---:|:---:|",
            *[
                _row(
                    r["variant"],
                    r["c1"],
                    r["c2"],
                    _f(r["dev_micro_f1_all"]),
                    _f(r["dev_micro_f1_cti"]),
                    "✓" if (r["variant"], r["c1"], r["c2"]) in kept else "",
                )
                for r in ner["grid"]
            ],
            "",
            f"Pipeline tagger: **{ner['selected']}**.",
            "",
        ]
    return "\n".join(lines)
