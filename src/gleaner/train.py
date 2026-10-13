"""Model selection and final training.

* ATT&CK catalog from the pinned Enterprise bundle.
* Gazetteer rules learned from AnnoCTR train (selection) and train+dev (final).
* CRF taggers (plain, and with gazetteer features): ``c1``/``c2`` chosen on AnnoCTR dev,
  final models refit on train+dev. The test split is not touched here.
* Technique classifier: features and ``C`` chosen by 3-fold document-grouped cross-validation
  on TRAM, global threshold from the out-of-fold probabilities, final fit on all of TRAM.
"""

from __future__ import annotations

import itertools
import json
import logging
import tempfile
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from joblib import Parallel, delayed
from scipy import sparse
from sklearn.model_selection import GroupKFold

from gleaner import datasets
from gleaner.attack import Catalog
from gleaner.gazetteer import GAZETTEER_LABELS, Gazetteer, GazetteerRules, fit_rules
from gleaner.metrics import best_threshold, multilabel_scores, span_scores
from gleaner.ner import CrfTagger
from gleaner.pipeline import (
    CATALOG_FILE,
    CRF_FILES,
    MODELS,
    RULES_FILE,
    TECHNIQUES_DIR,
    TRAINING_FILE,
)
from gleaner.spans import bio_to_spans
from gleaner.techniques import (
    ModelConfig,
    binarize,
    document_groups,
    featurize,
    fit,
    fit_features,
)
from gleaner.text import tokenize

log = logging.getLogger(__name__)

CRF_GRID = {"c1": (0.05, 0.2), "c2": (0.01, 0.1)}
TECHNIQUE_GRID = [
    ModelConfig(features, c, class_weight)
    for features in ("word", "word+char")
    for c in (4.0, 16.0)
    for class_weight in (None, "balanced")
]
SEED = 0

Pairs = list[tuple[tuple[str, ...], tuple[str, ...]]]


def build_catalog(raw: Path = datasets.RAW, models: Path = MODELS) -> Catalog:
    catalog = Catalog.from_bundle(raw / datasets.ATTACK_BUNDLE)
    catalog.save(models / CATALOG_FILE)
    log.info("ATT&CK %s catalog: %d objects", catalog.version, len(catalog.objects))
    return catalog


def reference_corpus(raw: Path, sentences: Pairs) -> list[list[str]]:
    """Lower-case usage statistics come from TRAM and the AnnoCTR training text."""
    return [list(words) for words, _ in sentences] + [
        [t.text for t in tokenize(r.text)] for r in datasets.load_tram(raw)
    ]


def _pairs(split: str, raw: Path) -> Pairs:
    return [(s.tokens, s.tags) for s in datasets.load_annoctr_ner(split, raw)]


def _fit_and_score(
    variant: str,
    c1: float,
    c2: float,
    train: Pairs,
    dev: Pairs,
    gazetteer: Gazetteer | None,
    workdir: str,
) -> dict:
    path = Path(workdir) / f"{variant}-{c1}-{c2}.crfsuite"
    tagger = CrfTagger.train(train, path, gazetteer=gazetteer, c1=c1, c2=c2)
    gold = [bio_to_spans(tags) for _, tags in dev]
    pred = [{m.key for m in tagger.mentions(words)} for words, _ in dev]
    labels = sorted({s[2] for g in gold for s in g})
    return {
        "variant": variant,
        "c1": c1,
        "c2": c2,
        "dev_micro_f1_all": span_scores(gold, pred, labels)["micro"]["f1"],
        "dev_micro_f1_cti": span_scores(gold, pred, GAZETTEER_LABELS)["micro"]["f1"],
    }


def _train_final(
    sentences: Pairs, path: Path, gazetteer: Gazetteer | None, c1: float, c2: float
) -> str:
    """Train in a worker and return the model path (a tagger cannot be pickled back)."""
    CrfTagger.train(sentences, path, gazetteer=gazetteer, c1=c1, c2=c2)
    return str(path)


def train_entities(
    catalog: Catalog, raw: Path = datasets.RAW, models: Path = MODELS, n_jobs: int = 8
) -> dict:
    train, dev = _pairs("train", raw), _pairs("dev", raw)
    rules = fit_rules(catalog, train, reference_corpus(raw, train))
    gazetteer = Gazetteer(catalog, rules=rules)
    grid = list(itertools.product(("crf", "crf+gazetteer"), CRF_GRID["c1"], CRF_GRID["c2"]))
    log.info("CRF selection on AnnoCTR dev: %d fits", len(grid))
    with tempfile.TemporaryDirectory() as workdir:
        results = Parallel(n_jobs=min(n_jobs, len(grid)))(
            delayed(_fit_and_score)(
                variant,
                c1,
                c2,
                train,
                dev,
                gazetteer if variant == "crf+gazetteer" else None,
                workdir,
            )
            for variant, c1, c2 in grid
        )
    best = {
        variant: max(
            (r for r in results if r["variant"] == variant), key=lambda r: r["dev_micro_f1_all"]
        )
        for variant in CRF_FILES
    }
    selected = max(best, key=lambda v: best[v]["dev_micro_f1_cti"])

    full = train + dev
    final_rules = fit_rules(catalog, full, reference_corpus(raw, full))
    final_rules.save(models / RULES_FILE)
    final_gazetteer = Gazetteer(catalog, rules=final_rules)
    log.info("final CRFs on AnnoCTR train+dev (%d sentences)", len(full))
    Parallel(n_jobs=2)(
        delayed(_train_final)(
            full,
            models / CRF_FILES[variant],
            final_gazetteer if variant == "crf+gazetteer" else None,
            best[variant]["c1"],
            best[variant]["c2"],
        )
        for variant in CRF_FILES
    )
    return {
        "grid": results,
        "best": best,
        "selected": selected,
        "rules": {
            "common_words": len(final_rules.common_words),
            "blocklist": len(final_rules.blocklist),
            "relabel": len(final_rules.relabel),
        },
        "train_sentences": len(full),
    }


def _oof_probas(
    texts: list[str],
    y: np.ndarray,
    groups: np.ndarray,
    grid: list[ModelConfig],
    folds: int,
    n_jobs: int,
) -> list[np.ndarray]:
    """Out-of-fold probabilities for every config; features are vectorised once per fold."""
    probas = [np.zeros(y.shape, dtype=np.float32) for _ in grid]
    labels = [str(j) for j in range(y.shape[1])]
    splitter = GroupKFold(n_splits=folds, shuffle=True, random_state=SEED)
    for tr, te in splitter.split(texts, y, groups):
        train_texts, test_texts = [texts[i] for i in tr], [texts[i] for i in te]
        cache: dict[tuple[str, int], tuple] = {}
        for k, config in enumerate(grid):
            key = (config.features, config.min_df)
            if key not in cache:
                blocks, x_train = featurize(train_texts, config)
                x_test = sparse.hstack([b.transform(test_texts) for b in blocks], format="csr")
                cache[key] = (blocks, x_train, x_test)
            blocks, x_train, x_test = cache[key]
            model = fit_features(blocks, x_train, y[tr], labels, config, n_jobs=n_jobs)
            probas[k][te] = model.proba_from_features(x_test)
    return probas


def select_technique_config(
    texts: list[str],
    y: np.ndarray,
    groups: np.ndarray,
    grid: list[ModelConfig] = TECHNIQUE_GRID,
    folds: int = 3,
    n_jobs: int = 8,
) -> tuple[ModelConfig, float, list[dict]]:
    """Best (config, threshold) by grouped cross-validated micro-F1."""
    scores = []
    for config, proba in zip(grid, _oof_probas(texts, y, groups, grid, folds, n_jobs), strict=True):
        threshold, f1 = best_threshold(y, proba)
        macro = multilabel_scores(y, proba >= threshold, range(y.shape[1]))["macro"]["f1"]
        scores.append({**asdict(config), "threshold": threshold, "micro_f1": f1, "macro_f1": macro})
        log.info("%s: micro-F1 %.3f at %.2f", config, f1, threshold)
    best = max(scores, key=lambda s: s["micro_f1"])
    config = ModelConfig(
        **{k: best[k] for k in ("features", "C", "class_weight", "min_df", "top_k")}
    )
    return config, best["threshold"], scores


def train_techniques(raw: Path = datasets.RAW, models: Path = MODELS, n_jobs: int = 8) -> dict:
    rows = datasets.load_tram(raw)
    texts = [r.text for r in rows]
    labels = sorted({lab for r in rows for lab in r.labels})
    y = binarize([r.labels for r in rows], labels)
    groups = document_groups([r.doc for r in rows], texts)
    config, threshold, scores = select_technique_config(texts, y, groups, n_jobs=n_jobs)
    model = fit(texts, y, labels, config, threshold=threshold, n_jobs=n_jobs)
    model.save(models / TECHNIQUES_DIR)
    return {
        "grid": scores,
        "selected": {**asdict(config), "threshold": threshold},
        "labels": len(labels),
        "sentences": len(texts),
        "documents": len({r.doc for r in rows}),
        "document_groups": len(set(groups)),
        "nonzero_weights": int(model.coef.nnz),
    }


def train_all(
    raw: Path = datasets.RAW,
    models: Path = MODELS,
    n_jobs: int = 8,
    parts: tuple[str, ...] = ("ner", "techniques"),
) -> dict:
    models.mkdir(parents=True, exist_ok=True)
    catalog = build_catalog(raw, models)
    results = {}
    if "ner" in parts:
        results["ner"] = train_entities(catalog, raw, models, n_jobs)
    if "techniques" in parts:
        results["techniques"] = train_techniques(raw, models, n_jobs)
    path = models / TRAINING_FILE  # read late: parts may be trained by separate runs
    summary = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    summary.update(results)
    summary["attack_version"] = catalog.version
    summary["trained_at"] = datetime.now(UTC).isoformat(timespec="seconds")
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def load_rules(models: Path = MODELS) -> GazetteerRules:
    return GazetteerRules.load(models / RULES_FILE)
