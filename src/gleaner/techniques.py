"""ATT&CK technique classification of sentences: TF-IDF features, one-vs-rest logistic regression.

The model is multi-label (a sentence can describe several techniques, or none) and is saved
without pickle: vocabularies and settings in JSON, IDF vectors and the (pruned, sparse) weight
matrix in a NumPy ``.npz`` read with ``allow_pickle=False``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np
from joblib import Parallel, delayed
from scipy import sparse
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import normalize

TOKEN_PATTERN = r"(?u)\b\w[\w.-]*\w\b|\b\w\b"
_BLOCKS = {"word": ("word", (1, 2)), "char": ("char_wb", (3, 5))}


@dataclass(frozen=True, slots=True)
class ModelConfig:
    features: str = "word"  # "word" or "word+char"
    C: float = 4.0
    class_weight: str | None = None  # None or "balanced"
    min_df: int = 2
    top_k: int | None = 3000  # keep the k largest |weights| per technique (compact export)

    @property
    def blocks(self) -> list[str]:
        return self.features.split("+")


@dataclass(slots=True)
class TfidfBlock:
    """A fitted TF-IDF vectoriser reduced to plain data."""

    analyzer: str
    ngram_range: tuple[int, int]
    vocabulary: dict[str, int]
    idf: np.ndarray

    @classmethod
    def fit(cls, texts: Sequence[str], kind: str, min_df: int) -> TfidfBlock:
        analyzer, ngram_range = _BLOCKS[kind]
        vec = TfidfVectorizer(
            analyzer=analyzer,
            ngram_range=ngram_range,
            min_df=min_df,
            sublinear_tf=True,
            token_pattern=TOKEN_PATTERN if analyzer == "word" else None,
            dtype=np.float32,
        )
        vec.fit(texts)
        return cls(analyzer, ngram_range, dict(vec.vocabulary_), vec.idf_.astype(np.float32))

    def transform(self, texts: Sequence[str]) -> sparse.csr_matrix:
        """Same output as ``TfidfVectorizer(sublinear_tf=True, norm="l2").transform``."""
        counts = CountVectorizer(
            analyzer=self.analyzer,
            ngram_range=self.ngram_range,
            vocabulary=self.vocabulary,
            token_pattern=TOKEN_PATTERN if self.analyzer == "word" else None,
            dtype=np.float32,
        ).transform(texts)
        counts.data = 1.0 + np.log(counts.data)
        return normalize(counts @ sparse.diags(self.idf), norm="l2", copy=False).tocsr()


@dataclass(slots=True)
class TechniqueModel:
    labels: list[str]
    blocks: list[TfidfBlock]
    coef: sparse.csr_matrix  # (n_labels, n_features)
    intercept: np.ndarray
    threshold: float = 0.5
    config: ModelConfig = field(default_factory=ModelConfig)

    def features(self, texts: Sequence[str]) -> sparse.csr_matrix:
        return sparse.hstack([b.transform(texts) for b in self.blocks], format="csr")

    def predict_proba(self, texts: Sequence[str]) -> np.ndarray:
        if not len(texts):
            return np.zeros((0, len(self.labels)), dtype=np.float32)
        return self.proba_from_features(self.features(texts))

    def proba_from_features(self, x: sparse.csr_matrix) -> np.ndarray:
        scores = np.asarray((x @ self.coef.T).todense()) + self.intercept
        return 1.0 / (1.0 + np.exp(-scores))

    def predict(
        self, texts: Sequence[str], threshold: float | None = None
    ) -> list[list[tuple[str, float]]]:
        """For each text, the (technique, probability) pairs above the threshold, best first."""
        t = self.threshold if threshold is None else threshold
        out = []
        for row in self.predict_proba(texts):
            idx = np.flatnonzero(row >= t)
            out.append(sorted(((self.labels[i], float(row[i])) for i in idx), key=lambda p: -p[1]))
        return out

    # ------------------------------------------------------------------ persistence

    def save(self, directory: Path) -> Path:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        meta = {
            "labels": self.labels,
            "threshold": self.threshold,
            "config": asdict(self.config),
            "blocks": [
                {"analyzer": b.analyzer, "ngram_range": list(b.ngram_range)} for b in self.blocks
            ],
        }
        (directory / "model.json").write_text(json.dumps(meta, indent=1) + "\n", encoding="utf-8")
        coef = self.coef.tocsr()
        arrays = {
            "coef_data": coef.data.astype(np.float16),
            "coef_indices": coef.indices.astype(np.int32),
            "coef_indptr": coef.indptr.astype(np.int32),
            "coef_shape": np.array(coef.shape, dtype=np.int64),
            "intercept": self.intercept.astype(np.float32),
        }
        for i, b in enumerate(self.blocks):
            terms = sorted(b.vocabulary, key=b.vocabulary.__getitem__)
            arrays[f"vocab_{i}"] = np.frombuffer("\n".join(terms).encode("utf-8"), dtype=np.uint8)
            arrays[f"idf_{i}"] = b.idf.astype(np.float16)
        np.savez_compressed(directory / "weights.npz", **arrays)
        return directory

    @classmethod
    def load(cls, directory: Path) -> TechniqueModel:
        directory = Path(directory)
        meta = json.loads((directory / "model.json").read_text(encoding="utf-8"))
        with np.load(directory / "weights.npz", allow_pickle=False) as w:
            coef = sparse.csr_matrix(
                (w["coef_data"].astype(np.float32), w["coef_indices"], w["coef_indptr"]),
                shape=tuple(w["coef_shape"]),
            )
            blocks = []
            for i, b in enumerate(meta["blocks"]):
                terms = w[f"vocab_{i}"].tobytes().decode("utf-8").split("\n")
                vocabulary = {t: j for j, t in enumerate(terms)}
                idf = w[f"idf_{i}"].astype(np.float32)
                blocks.append(TfidfBlock(b["analyzer"], tuple(b["ngram_range"]), vocabulary, idf))
            intercept = w["intercept"].astype(np.float32)
        config = ModelConfig(**meta["config"])
        return cls(meta["labels"], blocks, coef, intercept, meta["threshold"], config)


# --------------------------------------------------------------------------- training


def _fit_label(
    x: sparse.csr_matrix, y: np.ndarray, c: float, class_weight: str | None
) -> tuple[np.ndarray, float]:
    if y.min() == y.max():  # no positive (or no negative) example in this training fold
        return np.zeros(x.shape[1], dtype=np.float32), (10.0 if y.max() else -10.0)
    clf = LogisticRegression(C=c, solver="liblinear", max_iter=1000, class_weight=class_weight)
    clf.fit(x, y)
    return clf.coef_[0].astype(np.float32), float(clf.intercept_[0])


def _prune(coef: np.ndarray, top_k: int | None) -> sparse.csr_matrix:
    """Keep the ``top_k`` largest absolute weights of each row (exactly, ties included)."""
    if top_k is not None and coef.shape[1] > top_k:
        keep = np.argpartition(np.abs(coef), -top_k, axis=1)[:, -top_k:]
        rows = np.arange(coef.shape[0])[:, None]
        pruned = np.zeros_like(coef)
        pruned[rows, keep] = coef[rows, keep]
        coef = pruned
    return sparse.csr_matrix(coef)


def featurize(
    texts: Sequence[str], config: ModelConfig
) -> tuple[list[TfidfBlock], sparse.csr_matrix]:
    """Fit the TF-IDF blocks of ``config`` on ``texts`` and return them with the matrix."""
    blocks = [TfidfBlock.fit(texts, kind, config.min_df) for kind in config.blocks]
    return blocks, sparse.hstack([b.transform(texts) for b in blocks], format="csr")


def fit_features(
    blocks: list[TfidfBlock],
    x: sparse.csr_matrix,
    y: np.ndarray,
    labels: Sequence[str],
    config: ModelConfig,
    threshold: float = 0.5,
    n_jobs: int = 4,
) -> TechniqueModel:
    """One logistic regression per technique on an already vectorised training set."""
    x = x.astype(np.float64)
    x.sort_indices()  # liblinear wants float64 CSR; convert once, share across threads
    # liblinear releases the GIL: threads give real parallelism without copying the matrix
    results = Parallel(n_jobs=n_jobs, prefer="threads")(
        delayed(_fit_label)(x, y[:, j], config.C, config.class_weight) for j in range(y.shape[1])
    )
    coef = np.vstack([r[0] for r in results])
    intercept = np.array([r[1] for r in results], dtype=np.float32)
    return TechniqueModel(
        list(labels), blocks, _prune(coef, config.top_k), intercept, threshold, config
    )


def fit(
    texts: Sequence[str],
    y: np.ndarray,
    labels: Sequence[str],
    config: ModelConfig | None = None,
    threshold: float = 0.5,
    n_jobs: int = 4,
) -> TechniqueModel:
    """Fit one logistic regression per technique on TF-IDF features."""
    config = config or ModelConfig()
    blocks, x = featurize(texts, config)
    return fit_features(blocks, x, y, labels, config, threshold, n_jobs)


def binarize(label_sets: Sequence[Sequence[str]], labels: Sequence[str]) -> np.ndarray:
    index = {lab: i for i, lab in enumerate(labels)}
    y = np.zeros((len(label_sets), len(labels)), dtype=np.int8)
    for row, labs in enumerate(label_sets):
        for lab in labs:
            if lab in index:
                y[row, index[lab]] = 1
    return y


# --------------------------------------------------------------------------- leakage control


def normalise(text: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9 ]+", " ", text.lower()).split())


def document_groups(
    docs: Sequence[str], texts: Sequence[str], min_overlap: float = 0.2
) -> np.ndarray:
    """Group id per sentence: documents sharing ``min_overlap`` of their sentences are merged.

    TRAM contains the same advisory under two titles; grouping by title alone would put copies
    of the same sentences on both sides of a split.
    """
    names = sorted(set(docs))
    parent = {d: d for d in names}

    def find(d: str) -> str:
        while parent[d] != d:
            parent[d] = parent[parent[d]]
            d = parent[d]
        return d

    sentences: dict[str, set[str]] = {d: set() for d in names}
    for doc, text in zip(docs, texts, strict=True):
        if len(norm := normalise(text).split()) >= 4:
            sentences[doc].add(" ".join(norm))
    owners: dict[str, set[str]] = {}
    for doc, sents in sentences.items():
        for s in sents:
            owners.setdefault(s, set()).add(doc)
    shared: dict[tuple[str, str], int] = {}
    for docs_with_s in owners.values():
        ordered = sorted(docs_with_s)
        for i, a in enumerate(ordered):
            for b in ordered[i + 1 :]:
                shared[a, b] = shared.get((a, b), 0) + 1
    for (a, b), n in shared.items():
        if n >= min_overlap * max(1, min(len(sentences[a]), len(sentences[b]))):
            parent[find(a)] = find(b)
    roots = {d: find(d) for d in names}
    ids = {r: i for i, r in enumerate(sorted(set(roots.values())))}
    return np.array([ids[roots[d]] for d in docs])


def near_duplicate_mask(
    train_texts: Sequence[str], test_texts: Sequence[str], threshold: float = 0.9
) -> np.ndarray:
    """True for test texts whose character n-gram cosine to some training text >= threshold."""
    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1, sublinear_tf=True)
    vec.fit(list(train_texts) + list(test_texts))
    a = vec.transform(test_texts)
    b = vec.transform(train_texts)
    mask = np.zeros(len(test_texts), dtype=bool)
    for start in range(0, a.shape[0], 1000):
        sims = (a[start : start + 1000] @ b.T).max(axis=1).toarray().ravel()
        mask[start : start + 1000] = sims >= threshold
    return mask
