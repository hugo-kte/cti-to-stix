"""Evaluation protocols. Every number in ``reports/metrics.json`` is produced here.

* ``iocs``        IOC extraction on the 34 AnnoCTR test reports: counts, plus the audited
                  precision and estimated recall (``reports/ioc_audit.csv``)
* ``entities``    entity recognition on the AnnoCTR test split (gazetteer vs CRF vs hybrids),
                  ATT&CK coverage and alias linking accuracy
* ``techniques``  TRAM sentence classification, nested document-grouped cross-validation,
                  compared with a leaky random split and a name-matching baseline
* ``cross``       the TRAM-trained classifier on AnnoCTR's ATT&CK technique mentions
* ``stix``        end-to-end bundles for every AnnoCTR test report, checked by the validator
"""

from __future__ import annotations

import json
import logging
import re
import statistics
import time
from collections import Counter
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from sklearn.model_selection import GroupKFold, KFold

from gleaner import __version__, audit, datasets
from gleaner.attack import Catalog, parent
from gleaner.gazetteer import ENTITY_LABELS, GAZETTEER_LABELS, Gazetteer, GazetteerRules
from gleaner.iocs import EXPORTED_STATUSES, extract_iocs
from gleaner.metrics import multilabel_scores, span_scores
from gleaner.ner import CrfTagger
from gleaner.pipeline import CATALOG_FILE, CRF_FILES, RULES_FILE, TECHNIQUES_DIR, Extractor
from gleaner.spans import bio_to_spans, merge
from gleaner.stix import to_bundle, validate
from gleaner.techniques import (
    ModelConfig,
    TechniqueModel,
    binarize,
    document_groups,
    fit,
    near_duplicate_mask,
)
from gleaner.train import SEED, select_technique_config

log = logging.getLogger(__name__)

SECTIONS = ("iocs", "entities", "techniques", "cross", "stix")
FIXED_TIME = datetime(2026, 1, 1, tzinfo=UTC)
_ATTACK_URL_RE = re.compile(
    r"attack\.mitre\.org/(?:techniques|groups|software|tactics)/([A-Z]+\d+)(?:/(\d+))?"
)


def attack_id_from_url(url: str) -> str | None:
    """``https://attack.mitre.org/techniques/T1566/001`` -> ``T1566.001``."""
    m = _ATTACK_URL_RE.search(url or "")
    if not m:
        return None
    return f"{m.group(1)}.{m.group(2)}" if m.group(2) else m.group(1)


# --------------------------------------------------------------------------- IOCs


def evaluate_iocs(raw: Path, audit_file: Path) -> dict:
    texts = datasets.annoctr_texts("test", raw)
    by_type: Counter[str] = Counter()
    by_status: Counter[str] = Counter()
    defanging = 0
    for text in texts.values():
        found = extract_iocs(text)
        defanging += any(i.defanged for i in found)
        for ioc in found:
            by_status[ioc.status] += 1
            if ioc.status in EXPORTED_STATUSES:
                by_type[ioc.type] += 1
    result = {
        "documents": len(texts),
        "documents_with_defanged_indicators": defanging,
        "exported_by_type": dict(by_type.most_common()),
        "by_status": dict(by_status.most_common()),
    }
    if audit_file.exists():
        result["audit"] = audit.score(raw, audit_file)
    return result


# --------------------------------------------------------------------------- entities


def _keys(mentions_per_sentence) -> list[set]:
    return [{m.key for m in ms} for ms in mentions_per_sentence]


def evaluate_entities(catalog: Catalog, raw: Path, models: Path) -> dict:
    test = datasets.load_annoctr_ner("test", raw)
    words = [list(s.tokens) for s in test]
    gold = [bio_to_spans(s.tags) for s in test]
    rules = GazetteerRules.load(models / RULES_FILE)
    gazetteer = Gazetteer(catalog, rules=rules)
    naive = Gazetteer(catalog, variants=False)
    crf = CrfTagger(models / CRF_FILES["crf"])
    crf_gaz = CrfTagger(models / CRF_FILES["crf+gazetteer"], gazetteer)

    gaz_m = [gazetteer.match(w) for w in words]
    crf_m = [crf.mentions(w) for w in words]
    crfg_m = [crf_gaz.mentions(w) for w in words]
    systems = {
        "gazetteer, names only": _keys(naive.match(w) for w in words),
        "gazetteer + rules": _keys(gaz_m),
        "CRF": _keys(crf_m),
        "CRF + gazetteer features": _keys(crfg_m),
        "CRF ∪ gazetteer": _keys(merge(c, g) for c, g in zip(crf_m, gaz_m, strict=True)),
        "CRF + gazetteer features ∪ gazetteer": _keys(
            merge(c, g) for c, g in zip(crfg_m, gaz_m, strict=True)
        ),
    }
    all_labels = sorted({s[2] for g in gold for s in g})
    results = {}
    for name, pred in systems.items():
        results[name] = {
            "strict": span_scores(gold, pred, GAZETTEER_LABELS),
            "lenient": span_scores(gold, pred, GAZETTEER_LABELS, lenient=True),
        }
        if name.startswith("CRF") and "∪" not in name:
            results[name]["all_labels"] = span_scores(gold, pred, all_labels)
    support = Counter(s[2] for g in gold for s in g)
    return {
        "split": "test",
        "documents": len({s.doc for s in test}),
        "sentences": len(test),
        "support": dict(support.most_common()),
        "systems": results,
        "linking": evaluate_linking(catalog, gazetteer, datasets.load_annoctr_links("test", raw)),
    }


def evaluate_linking(catalog: Catalog, gazetteer: Gazetteer, links: list[dict]) -> dict:
    """How many gold mentions name an ATT&CK object, and does the alias lookup find it?"""
    out = {}
    for label in ENTITY_LABELS:
        rows = [r for r in links if r["entity_type"] == label]
        in_attack = [r for r in rows if attack_id_from_url(r["label_link"])]
        linked = correct = 0
        for r in in_attack:
            expected = catalog.get(attack_id_from_url(r["label_link"]))
            found = gazetteer.link(r["mention"])
            linked += found is not None
            correct += bool(found and expected and found.attack_id == expected.attack_id)
        outside = [r for r in rows if not attack_id_from_url(r["label_link"])]
        # mostly entities added to ATT&CK after the annotation (Squirrelwaffle) or aliases
        extra_links = sum(gazetteer.link(r["mention"]) is not None for r in outside)
        out[label] = {
            "mentions": len(rows),
            "in_attack": len(in_attack),
            "in_attack_share": len(in_attack) / len(rows) if rows else 0.0,
            "linked": linked,
            "correct": correct,
            "accuracy": correct / len(in_attack) if in_attack else 0.0,
            "precision": correct / linked if linked else 0.0,
            "outside_attack": len(outside),
            "extra_links": extra_links,
        }
    return out


# --------------------------------------------------------------------------- techniques


def _tram(raw: Path):
    rows = datasets.load_tram(raw)
    texts = [r.text for r in rows]
    labels = sorted({lab for r in rows for lab in r.labels})
    y = binarize([r.labels for r in rows], labels)
    groups = document_groups([r.doc for r in rows], texts)
    return rows, texts, labels, y, groups


def _fixed_cv(texts, y, labels, splits, config: ModelConfig, threshold: float, n_jobs: int):
    pred = np.zeros(y.shape, dtype=bool)
    for tr, te in splits:
        model = fit([texts[i] for i in tr], y[tr], labels, config, threshold, n_jobs)
        pred[te] = model.predict_proba([texts[i] for i in te]) >= threshold
    return multilabel_scores(y, pred, labels)


def name_baseline(texts: list[str], labels: list[str], catalog: Catalog) -> np.ndarray:
    """Predict a technique when its ATT&CK name appears verbatim (case-insensitive)."""
    patterns = []
    for lab in labels:
        obj = catalog.get(lab)
        names = {n for n in ((obj.names if obj else ()) or ()) if len(n) > 3}
        patterns.append(
            re.compile("|".join(rf"\b{re.escape(n)}\b" for n in names), re.IGNORECASE)
            if names
            else None
        )
    pred = np.zeros((len(texts), len(labels)), dtype=bool)
    for j, pattern in enumerate(patterns):
        if pattern is not None:
            pred[:, j] = [bool(pattern.search(t)) for t in texts]
    return pred


def evaluate_techniques(catalog: Catalog, raw: Path, n_jobs: int = 8, outer: int = 5) -> dict:
    rows, texts, labels, y, groups = _tram(raw)
    proba = np.zeros(y.shape, dtype=np.float32)
    pred = np.zeros(y.shape, dtype=bool)
    scored = np.ones(len(texts), dtype=bool)
    folds = []
    splitter = GroupKFold(n_splits=outer, shuffle=True, random_state=SEED)
    grouped_splits = list(splitter.split(texts, y, groups))
    for k, (tr, te) in enumerate(grouped_splits):
        log.info("technique outer fold %d/%d", k + 1, outer)
        train_texts = [texts[i] for i in tr]
        config, threshold, _ = select_technique_config(
            train_texts, y[tr], groups[tr], n_jobs=n_jobs
        )
        model = fit(train_texts, y[tr], labels, config, threshold, n_jobs)
        test_texts = [texts[i] for i in te]
        proba[te] = model.predict_proba(test_texts)
        pred[te] = proba[te] >= threshold
        duplicates = near_duplicate_mask(train_texts, test_texts)
        scored[te[duplicates]] = False
        keep = te[~duplicates]
        fold_scores = multilabel_scores(y[keep], pred[keep], labels)
        folds.append(
            {
                "fold": k,
                "config": asdict(config),
                "threshold": threshold,
                "test_sentences": len(te),
                "test_documents": len({rows[i].doc for i in te}),
                "near_duplicates_dropped": int(duplicates.sum()),
                "micro_f1": fold_scores["micro"]["f1"],
                "macro_f1": fold_scores["macro"]["f1"],
            }
        )
    pooled = multilabel_scores(y[scored], pred[scored], labels)
    labelled = scored & (y.sum(axis=1) > 0)
    top1 = float(np.mean(y[labelled, proba[labelled].argmax(axis=1)]))

    # The same fixed model under three protocols isolates the effect of the split.
    modal = Counter(json.dumps(f["config"], sort_keys=True) for f in folds).most_common(1)[0][0]
    config = ModelConfig(**json.loads(modal))
    threshold = float(statistics.median(f["threshold"] for f in folds))
    random_splits = list(KFold(n_splits=outer, shuffle=True, random_state=SEED).split(texts))
    leaky = _fixed_cv(texts, y, labels, random_splits, config, threshold, n_jobs)
    grouped = _fixed_cv(texts, y, labels, grouped_splits, config, threshold, n_jobs)
    baseline = name_baseline(texts, labels, catalog)

    support = y.sum(axis=0)
    per_technique = {}
    for j, lab in enumerate(labels):
        obj = catalog.get(lab)
        per_technique[lab] = {
            **pooled["per_label"][lab],
            "name": obj.name if obj else lab,
            "current_id": obj.attack_id if obj else None,
            "sentences": int(support[j]),
        }
    return {
        "dataset": {
            "sentences": len(texts),
            "labelled_sentences": int((y.sum(axis=1) > 0).sum()),
            "documents": len({r.doc for r in rows}),
            "document_groups": len(set(groups)),
            "techniques": len(labels),
            "scored_sentences": int(scored.sum()),
            "near_duplicates_dropped": int((~scored).sum()),
        },
        "nested_cv": {
            "folds": folds,
            "micro": pooled["micro"],
            "macro": pooled["macro"],
            "top1_accuracy_labelled": top1,
            "fold_micro_f1_std": float(np.std([f["micro_f1"] for f in folds])),
            "fold_macro_f1_std": float(np.std([f["macro_f1"] for f in folds])),
        },
        "protocols": {
            "fixed_config": {**asdict(config), "threshold": threshold},
            "random_sentence_split": {"micro": leaky["micro"], "macro": leaky["macro"]},
            "document_grouped_split": {"micro": grouped["micro"], "macro": grouped["macro"]},
        },
        "name_matching_baseline": {
            k: v
            for k, v in multilabel_scores(y[scored], baseline[scored], labels).items()
            if k != "per_label"
        },
        "per_technique": per_technique,
    }


# --------------------------------------------------------------------------- cross-dataset


def evaluate_cross_dataset(catalog: Catalog, raw: Path, models: Path) -> dict:
    """TRAM-trained classifier on AnnoCTR technique mentions (all splits: never trained on)."""
    model = TechniqueModel.load(models / TECHNIQUES_DIR)

    def current(attack_id: str) -> str:
        obj = catalog.get(attack_id)
        return obj.attack_id if obj else attack_id

    model_ids = [current(lab) for lab in model.labels]
    known, known_parents = set(model_ids), {parent(i) for i in model_ids}
    mentions = []
    for split in datasets.ANNOCTR_SPLITS:
        for r in datasets.load_annoctr_links(split, raw):
            gold = attack_id_from_url(r["label_link"])
            if r["entity_type"] == "TECHNIQUE" and gold:
                context = f"{r['_context_left']}{r['mention']}{r['_context_right']}".strip()
                mentions.append((current(gold), r["entity_class"], context))
    proba = model.predict_proba([m[2] for m in mentions])
    order = np.argsort(-proba, axis=1)
    rows = []
    for (gold, kind, _), p, rank in zip(mentions, proba, order, strict=True):
        top = [model_ids[j] for j in rank[:3]]
        rows.append(
            {
                "kind": "explicit" if kind == "CE" else "implicit",
                "in_scope": gold in known,
                "parent_in_scope": parent(gold) in known_parents,
                "top1": top[0] == gold,
                "top3": gold in top,
                "above_threshold": bool(
                    gold in known and p[model_ids.index(gold)] >= model.threshold
                ),
                "parent_top1": parent(top[0]) == parent(gold),
            }
        )

    def summary(subset: list[dict]) -> dict:
        scope = [r for r in subset if r["in_scope"]]
        pscope = [r for r in subset if r["parent_in_scope"]]
        return {
            "mentions": len(subset),
            "in_scope": len(scope),
            "in_scope_share": len(scope) / len(subset) if subset else 0.0,
            "top1": float(np.mean([r["top1"] for r in scope])) if scope else 0.0,
            "top3": float(np.mean([r["top3"] for r in scope])) if scope else 0.0,
            "recall_at_threshold": float(np.mean([r["above_threshold"] for r in scope]))
            if scope
            else 0.0,
            "parent_in_scope": len(pscope),
            "parent_top1": float(np.mean([r["parent_top1"] for r in pscope])) if pscope else 0.0,
        }

    gold_counts = Counter(m[0] for m in mentions)
    return {
        "all": summary(rows),
        "explicit": summary([r for r in rows if r["kind"] == "explicit"]),
        "implicit": summary([r for r in rows if r["kind"] == "implicit"]),
        "distinct_gold_techniques": len(gold_counts),
        "distinct_gold_in_scope": sum(1 for g in gold_counts if g in known),
        "threshold": model.threshold,
    }


# --------------------------------------------------------------------------- STIX


def evaluate_stix(raw: Path, models: Path) -> dict:
    extractor = Extractor.from_dir(models)
    reports = dict(datasets.annoctr_texts("test", raw))
    valid = errors = warnings = 0
    objects: Counter[str] = Counter()
    seconds = []
    for doc, text in reports.items():
        start = time.perf_counter()
        bundle = to_bundle(extractor.extract(text, doc), extractor.catalog, now=FIXED_TIME)
        seconds.append(time.perf_counter() - start)
        serialized = bundle.serialize()
        ok, errs, warns = validate(serialized)
        valid += ok
        errors += len(errs)
        warnings += len(warns)
        objects.update(o["type"] for o in json.loads(serialized)["objects"])
    n = len(reports)
    return {
        "reports": n,
        "valid_bundles": valid,
        "validator_errors": errors,
        "validator_warnings": warnings,
        "strict_mode": True,
        "objects_per_report": {k: v / n for k, v in objects.most_common()},
        "seconds_per_report": float(np.mean(seconds)),
        "components": extractor.components,
    }


# --------------------------------------------------------------------------- driver


def run(
    raw: Path = datasets.RAW,
    models: Path = Path("models"),
    out_dir: Path = Path("reports"),
    sections: tuple[str, ...] = SECTIONS,
    n_jobs: int = 8,
) -> dict:
    """Run the requested sections and merge them into ``reports/metrics.json``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    catalog = Catalog.load(models / CATALOG_FILE)
    runners = {
        "iocs": lambda: evaluate_iocs(raw, out_dir / "ioc_audit.csv"),
        "entities": lambda: evaluate_entities(catalog, raw, models),
        "techniques": lambda: evaluate_techniques(catalog, raw, n_jobs),
        "cross": lambda: evaluate_cross_dataset(catalog, raw, models),
        "stix": lambda: evaluate_stix(raw, models),
    }
    results, runtime = {}, {}
    for section in sections:
        log.info("evaluating %s", section)
        start = time.perf_counter()
        results[section] = runners[section]()
        runtime[section] = round(time.perf_counter() - start, 1)
    path = out_dir / "metrics.json"  # read late: sections may be evaluated by separate runs
    metrics = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    metrics.update(results)
    metrics.setdefault("runtime_seconds", {}).update(runtime)
    training = models / "training.json"
    if training.exists():
        metrics["training"] = json.loads(training.read_text(encoding="utf-8"))
    metrics["meta"] = {
        "gleaner_version": __version__,
        "attack_version": catalog.version,
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        "datasets": {
            name: {"repo": s.repo, "commit": s.commit, "license": s.license}
            for name, s in datasets.load_sources().items()
        },
    }
    path.write_text(json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return metrics
