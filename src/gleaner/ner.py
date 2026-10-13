"""Entity recognition with a linear-chain CRF (python-crfsuite), trained from scratch on AnnoCTR.

Features are hand-crafted and local: the word, its shape, affixes and neighbours, and
optionally the BIO tag a gazetteer assigns to it (``CRF + gazetteer features``). No pretrained
embeddings or language models are used. The model file is crfsuite's own binary format.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path

import pycrfsuite

from gleaner.gazetteer import Gazetteer
from gleaner.spans import Mention, bio_to_spans, spans_to_bio

_SHAPE_RE = [(re.compile(r"[A-Z]"), "X"), (re.compile(r"[a-z]"), "x"), (re.compile(r"\d"), "d")]


def shape(word: str) -> str:
    """``APT28`` -> ``XXXdd``; the short form collapses repeats: ``Xd``."""
    for pattern, char in _SHAPE_RE:
        word = pattern.sub(char, word)
    return word


def _short(shape_: str) -> str:
    return re.sub(r"(.)\1+", r"\1", shape_)


def _word(word: str, prefix: str) -> dict[str, str | float]:
    lower = word.lower()
    return {
        f"{prefix}lower": lower,
        f"{prefix}short": _short(shape(word)),
        f"{prefix}title": float(word.istitle()),
        f"{prefix}upper": float(word.isupper() and len(word) > 1),
    }


def sentence_features(
    words: Sequence[str], gazetteer_tags: Sequence[str] | None = None
) -> list[dict[str, str | float]]:
    """Feature dictionaries for every token of a sentence."""
    feats = []
    n = len(words)
    for i, word in enumerate(words):
        lower = word.lower()
        f: dict[str, str | float] = {
            "bias": 1.0,
            "lower": lower,
            "shape": shape(word)[:12],
            "short": _short(shape(word)),
            "pre2": lower[:2],
            "pre3": lower[:3],
            "suf2": lower[-2:],
            "suf3": lower[-3:],
            "suf4": lower[-4:],
            "title": float(word.istitle()),
            "upper": float(word.isupper() and len(word) > 1),
            "mixed": float(any(c.isupper() for c in word[1:]) and any(c.islower() for c in word)),
            "digit": float(any(c.isdigit() for c in word)),
            "hyphen": float("-" in word),
            "dot": float("." in word.strip(".")),
            "len": str(min(len(word), 12)),
        }
        if i == 0:
            f["BOS"] = 1.0
        if i == n - 1:
            f["EOS"] = 1.0
        for offset in (-2, -1, 1, 2):
            j = i + offset
            if 0 <= j < n:
                f.update(_word(words[j], f"{offset:+d}:"))
        if i > 0:
            f["-1|0"] = f"{words[i - 1].lower()}|{lower}"
        if i < n - 1:
            f["0|+1"] = f"{lower}|{words[i + 1].lower()}"
        if gazetteer_tags is not None:
            f["gaz"] = gazetteer_tags[i]
            f["gaz-1"] = gazetteer_tags[i - 1] if i > 0 else "BOS"
            f["gaz+1"] = gazetteer_tags[i + 1] if i < n - 1 else "EOS"
        feats.append(f)
    return feats


def gazetteer_tags(gazetteer: Gazetteer, words: Sequence[str]) -> list[str]:
    return spans_to_bio(len(words), (m.key for m in gazetteer.match(words)))


class CrfTagger:
    """A trained CRF, optionally using gazetteer features (the same gazetteer at train time)."""

    def __init__(self, model_path: Path, gazetteer: Gazetteer | None = None) -> None:
        self.model_path = Path(model_path)
        self.gazetteer = gazetteer
        self._tagger = pycrfsuite.Tagger()
        self._tagger.open(str(self.model_path))

    @property
    def labels(self) -> list[str]:
        return sorted({t[2:] for t in self._tagger.labels() if t != "O"})

    def features(self, words: Sequence[str]) -> list[dict[str, str | float]]:
        tags = gazetteer_tags(self.gazetteer, words) if self.gazetteer else None
        return sentence_features(words, tags)

    def tag(self, words: Sequence[str]) -> list[str]:
        if not words:
            return []
        return self._tagger.tag(self.features(words))

    def mentions(self, words: Sequence[str]) -> list[Mention]:
        return [
            Mention(s, e, lab, None, "crf") for s, e, lab in sorted(bio_to_spans(self.tag(words)))
        ]

    @classmethod
    def train(
        cls,
        sentences: Sequence[tuple[Sequence[str], Sequence[str]]],
        model_path: Path,
        *,
        gazetteer: Gazetteer | None = None,
        c1: float = 0.1,
        c2: float = 0.05,
        max_iterations: int = 150,
    ) -> CrfTagger:
        """Train on (tokens, BIO tags) pairs and save the model to ``model_path``."""
        trainer = pycrfsuite.Trainer(verbose=False)
        for words, tags in sentences:
            if words:
                gaz = gazetteer_tags(gazetteer, words) if gazetteer else None
                trainer.append(sentence_features(words, gaz), list(tags))
        trainer.set_params(
            {
                "c1": c1,
                "c2": c2,
                "max_iterations": max_iterations,
                "feature.possible_transitions": True,
            }
        )
        model_path = Path(model_path)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        trainer.train(str(model_path))
        return cls(model_path, gazetteer)
