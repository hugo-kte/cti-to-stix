"""Technique classifier, leakage control and metrics on a toy corpus."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
from sklearn.feature_extraction.text import TfidfVectorizer

from gleaner import techniques
from gleaner.metrics import best_threshold, multilabel_scores, prf, wilson
from gleaner.techniques import (
    TOKEN_PATTERN,
    ModelConfig,
    TechniqueModel,
    TfidfBlock,
    document_groups,
    fit,
    near_duplicate_mask,
    normalise,
)
from gleaner.train import select_technique_config


def test_tfidf_block_matches_scikit_learn():
    texts = ["the loader downloads a payload", "a payload was downloaded", "phishing email"]
    block = TfidfBlock.fit(texts, "word", min_df=1)
    reference = TfidfVectorizer(
        ngram_range=(1, 2), sublinear_tf=True, token_pattern=TOKEN_PATTERN, min_df=1
    ).fit(texts)
    np.testing.assert_allclose(
        block.transform(texts).toarray(), reference.transform(texts).toarray(), atol=1e-5
    )


def test_model_predicts_and_round_trips(technique_model: TechniqueModel, tmp_path: Path):
    texts = [
        "A spearphishing email with a malicious attachment reached the CFO.",
        "The malware dumped LSASS memory to steal credentials.",
        "The annual report was published.",
    ]
    preds = technique_model.predict(texts)
    assert preds[0][0][0] == "T1566.001"
    assert preds[1][0][0] == "T1003.001"
    assert (
        technique_model.predict_proba(texts)[2].max()
        < technique_model.predict_proba(texts)[0].max()
    )
    loaded = TechniqueModel.load(technique_model.save(tmp_path / "model"))
    assert loaded.labels == technique_model.labels and loaded.threshold == technique_model.threshold
    np.testing.assert_allclose(
        loaded.predict_proba(texts), technique_model.predict_proba(texts), atol=5e-3
    )
    assert technique_model.predict_proba([]).shape == (0, len(technique_model.labels))


def test_shipped_model_passes_the_loader_checks():
    model = TechniqueModel.load(Path(__file__).parents[1] / "models" / "techniques")
    assert len(model.labels) == 50 and 0 < model.threshold < 1


@pytest.mark.parametrize(
    "corruption", ["index out of bounds", "shape mismatch", "unexpected array", "too large"]
)
def test_loader_rejects_corrupt_models(
    technique_model: TechniqueModel, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, corruption
):
    directory = technique_model.save(tmp_path / "model")
    with np.load(directory / "weights.npz") as w:
        arrays = {name: w[name] for name in w.files}
    if corruption == "index out of bounds":  # would be read out of bounds by scipy
        arrays["coef_indices"] = arrays["coef_indices"].copy()
        arrays["coef_indices"][0] = 10**6
    elif corruption == "shape mismatch":
        arrays["intercept"] = arrays["intercept"][:-1]
    elif corruption == "unexpected array":
        arrays["extra"] = np.zeros(3)
    else:
        monkeypatch.setattr(techniques, "MAX_ARRAY_BYTES", 1_000)
    np.savez_compressed(directory / "weights.npz", **arrays)
    with pytest.raises(ValueError, match="invalid technique model"):
        TechniqueModel.load(directory)


def test_weights_are_pruned(technique_data):
    texts, y, labels, _ = technique_data
    model = fit(texts, y, labels, ModelConfig("word", 4.0, min_df=1, top_k=5), n_jobs=1)
    assert (np.diff(model.coef.indptr) <= 5).all()


def test_label_without_positives_never_fires(technique_data):
    texts, y, labels, _ = technique_data
    y = np.hstack([y, np.zeros((len(texts), 1), dtype=y.dtype)])
    model = fit(texts, y, [*labels, "T0000"], ModelConfig("word", 1.0, min_df=1), n_jobs=1)
    assert model.predict_proba(texts)[:, -1].max() < 1e-3


def test_document_groups_merge_duplicated_reports():
    docs = ["a"] * 5 + ["b"] * 5 + ["c"] * 5
    shared = [f"identical sentence number {i} in both copies" for i in range(5)]
    texts = shared + shared + [f"another report sentence {i} entirely" for i in range(5)]
    groups = document_groups(docs, texts)
    assert groups[0] == groups[5] != groups[10]


def test_near_duplicate_mask():
    train = ["The malware downloads a second-stage payload over HTTPS.", "Phishing email."]
    test = ["the malware downloads a second-stage payload over HTTPS!", "Unrelated sentence here."]
    assert near_duplicate_mask(train, test).tolist() == [True, False]
    assert normalise("Hello, World!") == "hello world"


def test_selection_runs_on_groups(technique_data):
    texts, y, _, docs = technique_data
    groups = np.array([int(d.split("-")[1]) for d in docs])
    grid = [ModelConfig("word", 1.0, min_df=1), ModelConfig("word", 4.0, min_df=1)]
    config, threshold, scores = select_technique_config(texts, y, groups, grid, folds=3, n_jobs=1)
    assert config in grid and 0 < threshold < 1 and len(scores) == 2
    assert all(0 <= s["micro_f1"] <= 1 for s in scores)


def test_metrics():
    assert prf(0, 0, 0)["f1"] == 0.0
    y = np.array([[1, 0], [0, 1], [0, 0]])
    p = np.array([[1, 0], [1, 0], [0, 0]])
    scores = multilabel_scores(y, p, ["A", "B"])
    assert scores["micro"]["precision"] == 0.5 and scores["micro"]["recall"] == 0.5
    assert scores["per_label"]["B"]["recall"] == 0.0
    proba = np.array([[0.9, 0.1], [0.2, 0.8], [0.1, 0.1]])
    assert best_threshold(y, proba)[1] == 1.0
    lo, hi = wilson(9, 10)
    assert lo < 0.9 < hi and wilson(0, 0) == (0.0, 1.0)
