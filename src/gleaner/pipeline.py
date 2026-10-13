"""End-to-end extraction: report text -> indicators, entities and ATT&CK techniques."""

from __future__ import annotations

import bisect
import hashlib
import json
import logging
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from gleaner.attack import Catalog
from gleaner.gazetteer import ENTITY_LABELS, Gazetteer, GazetteerRules
from gleaner.iocs import IOC, extract_iocs
from gleaner.ner import CrfTagger
from gleaner.spans import Mention, merge
from gleaner.techniques import TechniqueModel
from gleaner.text import Sentence, split_sentences

log = logging.getLogger(__name__)

MODELS = Path("models")
CATALOG_FILE = "attack-catalog.json"
RULES_FILE = "gazetteer-rules.json"
TECHNIQUES_DIR = "techniques"
TRAINING_FILE = "training.json"
CRF_FILES = {"crf": "ner.crfsuite", "crf+gazetteer": "ner-gazetteer.crfsuite"}
_ATTACK_ID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")


@dataclass(slots=True)
class EntityHit:
    label: str  # GROUP | MALWARE | TOOL
    name: str  # ATT&CK name when linked, else the most frequent surface form
    attack_id: str | None
    surfaces: list[str]
    sentences: list[int]
    sources: list[str]  # gazetteer, crf

    @property
    def mentions(self) -> int:
        return len(self.sentences)


@dataclass(slots=True)
class TechniqueHit:
    attack_id: str  # current ATT&CK ID (revocations followed)
    name: str
    tactics: list[str]
    score: float  # best classifier probability; 1.0 when the report cites the ID or the name
    sentences: list[int]
    evidence: str  # the most confident sentence
    sources: list[str]  # classifier, attack-id (T1055 cited), name (exact technique name)
    original_ids: list[str] = field(default_factory=list)  # IDs as predicted, if revoked since


@dataclass(slots=True)
class Extraction:
    title: str
    source: str
    sha256: str
    sentences: list[str]
    iocs: list[IOC]
    ioc_sentences: dict[str, list[int]]  # "type|value" -> sentence indexes
    entities: list[EntityHit]
    techniques: list[TechniqueHit]
    components: list[str]  # which extractors ran

    def to_dict(self) -> dict:
        data = asdict(self)
        data.pop("sentences")
        data["sentence_count"] = len(self.sentences)
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


def _title(text: str, fallback: str) -> str:
    for line in text.splitlines():
        line = re.sub(r"^[#>*\s]+|[*\s]+$", "", line)
        if len(line) > 3:
            return line[:200]
    return fallback


class Extractor:
    def __init__(
        self,
        catalog: Catalog,
        gazetteer: Gazetteer,
        crf: CrfTagger | None = None,
        techniques: TechniqueModel | None = None,
        min_technique_tokens: int = 4,
    ) -> None:
        self.catalog = catalog
        self.gazetteer = gazetteer
        self.crf = crf
        self.techniques = techniques
        self.min_technique_tokens = min_technique_tokens

    @classmethod
    def from_dir(cls, models: Path = MODELS) -> Extractor:
        """Load whatever is available in ``models/``: catalog and rules are required."""
        models = Path(models)
        catalog = Catalog.load(models / CATALOG_FILE)
        rules_path = models / RULES_FILE
        rules = GazetteerRules.load(rules_path) if rules_path.exists() else None
        gazetteer = Gazetteer(catalog, rules=rules)
        crf = None
        choice = "crf+gazetteer"
        if (training := models / TRAINING_FILE).exists():
            choice = (
                json.loads(training.read_text(encoding="utf-8"))
                .get("ner", {})
                .get("selected", choice)
            )
        for name in (choice, *CRF_FILES):
            if (path := models / CRF_FILES[name]).exists():
                crf = CrfTagger(path, gazetteer if name == "crf+gazetteer" else None)
                break
        if crf is None:
            log.info("no CRF model in %s (run `gleaner train`): gazetteer entities only", models)
        techniques = None
        if (models / TECHNIQUES_DIR / "model.json").exists():
            techniques = TechniqueModel.load(models / TECHNIQUES_DIR)
        return cls(catalog, gazetteer, crf, techniques)

    @property
    def components(self) -> list[str]:
        parts = ["iocs", "gazetteer"]
        if self.crf:
            parts.append("crf")
        if self.techniques:
            parts.append("technique-classifier")
        return parts

    # ------------------------------------------------------------------ extraction

    def mentions(self, words: list[str]) -> list[Mention]:
        """CRF mentions first; gazetteer matches fill the gaps the CRF left."""
        found = self.gazetteer.match(words)
        if self.crf:
            found = merge(self.crf.mentions(words), found)
        return found

    def extract(self, text: str, source: str = "") -> Extraction:
        sentences = split_sentences(text)
        starts = [s.start for s in sentences]
        iocs = extract_iocs(text)
        ioc_sentences = {
            f"{i.type}|{i.value}": sorted(
                {max(0, bisect.bisect_right(starts, o) - 1) for o in i.offsets}
            )
            for i in iocs
        }
        entities, explicit = self._entities(sentences)
        techniques = self._techniques(sentences, explicit)
        return Extraction(
            title=_title(text, Path(source).stem if source else "Untitled report"),
            source=source,
            sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            sentences=[s.text for s in sentences],
            iocs=iocs,
            ioc_sentences=ioc_sentences,
            entities=entities,
            techniques=techniques,
            components=self.components,
        )

    def _entities(self, sentences: list[Sentence]) -> tuple[list[EntityHit], dict[str, list[int]]]:
        hits: dict[tuple[str, str], EntityHit] = {}
        explicit: dict[str, list[int]] = defaultdict(list)  # technique ID -> sentences
        for k, sentence in enumerate(sentences):
            for m in self.mentions(sentence.words):
                surface = _surface(sentence, m)
                if m.label == "TECHNIQUE":
                    obj = (
                        self.catalog.get(m.attack_id)
                        if m.attack_id
                        else self.gazetteer.link(surface, "TECHNIQUE")
                    )
                    if obj:
                        explicit[obj.attack_id].append(k)
                    continue
                if m.label not in ENTITY_LABELS:
                    continue
                obj = (
                    self.catalog.get(m.attack_id)
                    if m.attack_id
                    else self.gazetteer.link(surface, m.label)
                )
                # a linked entity takes ATT&CK's type: the taggers follow AnnoCTR, where
                # Mimikatz is malware, but STIX consumers expect ATT&CK's tool S0002
                label = obj.label if obj and obj.label in ENTITY_LABELS else m.label
                key = (label, obj.attack_id if obj else surface.casefold())
                hit = hits.get(key)
                if hit is None:
                    name, attack_id = (obj.name, obj.attack_id) if obj else (surface, None)
                    hit = hits[key] = EntityHit(label, name, attack_id, [], [], [])
                hit.surfaces.append(surface)
                hit.sentences.append(k)
                if m.source not in hit.sources:
                    hit.sources.append(m.source)
        for hit in hits.values():
            if hit.attack_id is None:  # most frequent spelling as the name (ties: sorted)
                hit.name = max(sorted(set(hit.surfaces)), key=hit.surfaces.count)
            hit.surfaces = sorted(set(hit.surfaces))
        ordered = sorted(
            hits.values(), key=lambda h: (ENTITY_LABELS.index(h.label), -h.mentions, h.name)
        )
        return ordered, explicit

    def _techniques(
        self, sentences: list[Sentence], explicit: dict[str, list[int]]
    ) -> list[TechniqueHit]:
        hits: dict[str, TechniqueHit] = {}

        def hit_for(raw_id: str) -> TechniqueHit | None:
            obj = self.catalog.get(raw_id)
            if obj is None or obj.kind != "technique":
                return None
            if obj.attack_id not in hits:
                hits[obj.attack_id] = TechniqueHit(
                    obj.attack_id, obj.name, list(obj.tactics), 0.0, [], "", []
                )
            hit = hits[obj.attack_id]
            if raw_id != obj.attack_id and raw_id not in hit.original_ids:
                hit.original_ids.append(raw_id)
            return hit

        if self.techniques:
            usable = [
                k for k, s in enumerate(sentences) if len(s.tokens) >= self.min_technique_tokens
            ]
            predictions = self.techniques.predict([sentences[k].text for k in usable])
            for k, preds in zip(usable, predictions, strict=True):
                for raw_id, prob in preds:
                    if (hit := hit_for(raw_id)) is None:
                        continue
                    hit.sentences.append(k)
                    if prob > hit.score:
                        hit.score, hit.evidence = prob, sentences[k].text
                    if "classifier" not in hit.sources:
                        hit.sources.append("classifier")
        cited: dict[str, list[int]] = defaultdict(list)  # "T1055.012" written in the report
        for k, sentence in enumerate(sentences):
            for m in _ATTACK_ID_RE.finditer(sentence.text):
                cited[m.group(1)].append(k)
        for source, found in (("attack-id", cited), ("name", explicit)):
            for raw_id, ks in found.items():
                if (hit := hit_for(raw_id)) is None:
                    continue
                hit.sentences.extend(ks)
                if hit.score < 1.0:
                    hit.score, hit.evidence = 1.0, sentences[ks[0]].text
                hit.sources.append(source)
        for hit in hits.values():
            hit.sentences = sorted(set(hit.sentences))
        return sorted(hits.values(), key=lambda h: (-h.score, h.attack_id))


def _surface(sentence: Sentence, m: Mention) -> str:
    """The mention as written in the document (original spacing)."""
    start = sentence.tokens[m.start].start - sentence.start
    end = sentence.tokens[m.end - 1].end - sentence.start
    return sentence.text[start:end]
