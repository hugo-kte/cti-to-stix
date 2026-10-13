"""Dictionary matching of ATT&CK groups, software, techniques and tactics.

Names and aliases come from the ATT&CK catalog. Matching is token-based, case-insensitive and
leftmost-longest, with spelling variants for software and groups (``NetwireRAT``,
``Cobalt Strike`` / ``CobaltStrike``, ``psexec.exe``). Rules keep common words from firing:

* **Case consistency.** A group or malware alias that has capitals (``Anchor``, ``Remcos``)
  does not match an all-lowercase token (``anchor``, a ``remcos`` file name). Tools are exempt:
  command names are routinely written in lower case (``psexec``, ``certutil``).
* **Common words.** An alias made only of words usually written in lower case in CTI prose
  (``Net``, ``Ping``, ``Royal``, ``Silence``) must match with its exact capitalisation and not
  as the first word of a sentence.
* **Learned relabelling and blocklist.** On the training split, an ``(alias, label)`` pair
  whose matches mostly carry another gold label is relabelled (ATT&CK files Remcos under
  *tool*, annotators call it malware); a pair whose matches are mostly wrong is dropped
  (``DLL`` as a technique, ``PowerShell`` as a technique).

All rules are learned from training data only (``fit_rules``), never from the test split.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from gleaner.attack import LABEL_OF_KIND, AttackObject, Catalog
from gleaner.spans import Mention, bio_to_spans
from gleaner.text import tokenize

ENTITY_LABELS = ("GROUP", "MALWARE", "TOOL")
GAZETTEER_LABELS = (*ENTITY_LABELS, "TECHNIQUE", "TACTIC")
MAX_ALIAS_TOKENS = 8
_KIND_PRIORITY = {"group": 0, "malware": 1, "tool": 2, "technique": 3, "tactic": 4}
_POSSESSIVE_RE = re.compile(r"['’]s$", re.IGNORECASE)
_NON_ALNUM_RE = re.compile(r"[\W_]+")


def _norm(token: str) -> str:
    return _POSSESSIVE_RE.sub("", token).casefold()


def _compact(text: str) -> str:
    """``Cobalt Strike`` / ``cobalt-strike`` -> ``cobaltstrike``."""
    return _NON_ALNUM_RE.sub("", _POSSESSIVE_RE.sub("", text).casefold())


def _variants(surface: str) -> list[str]:
    """Compact keys a software or group name may hide behind (``NetwireRAT``, ``ping.exe``)."""
    key = _compact(re.sub(r"\.exe$", "", surface, flags=re.IGNORECASE))
    keys = [key]
    for suffix in ("rat", "malware", "ransomware", "backdoor", "loader", "stealer"):
        if key.endswith(suffix) and len(key) - len(suffix) >= 4:
            keys.append(key[: -len(suffix)])
    return keys


@dataclass(frozen=True, slots=True)
class _Entry:
    obj: AttackObject
    tokens: tuple[str, ...]  # alias tokens, original case
    canonical: bool  # the object's name rather than an alias


def _expand(obj: AttackObject, catalog: Catalog) -> list[str]:
    """Names to index for an ATT&CK object.

    * groups: also ``Lazarus`` for ``Lazarus Group`` (canonical names only: the alias
      ``Beijing Group`` would yield a city);
    * sub-techniques: ``Parent: Sub``, plus the short name only when it has several words
      (``LSASS Memory`` yes; ``DNS``, ``Server`` or ``Software`` would fire everywhere).
    """
    if obj.kind == "technique" and "." in obj.attack_id:
        parent = catalog.objects.get(obj.attack_id.split(".", 1)[0])
        names = [f"{parent.name}: {obj.name}"] if parent else []
        return names + [n for n in obj.names if len(tokenize(n)) > 1]
    names = list(obj.names)
    short = re.sub(r"\s+(?:Group|Team)$", "", obj.name)
    if obj.kind == "group" and short.casefold() not in {n.casefold() for n in names}:
        names.append(short)
    return names


def _priority(entry: _Entry) -> tuple[bool, int, str]:
    """Canonical names before aliases, then groups before software before techniques."""
    return (not entry.canonical, _KIND_PRIORITY[entry.obj.kind], entry.obj.attack_id)


@dataclass(slots=True)
class GazetteerRules:
    common_words: frozenset[str] = frozenset()
    blocklist: frozenset[tuple[str, str]] = frozenset()  # (normalised alias, label)
    relabel: dict[tuple[str, str], str] = field(default_factory=dict)

    def save(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "common_words": sorted(self.common_words),
            "blocklist": [list(pair) for pair in sorted(self.blocklist)],
            "relabel": [[a, lab, new] for (a, lab), new in sorted(self.relabel.items())],
        }
        path.write_text(json.dumps(data, indent=0) + "\n", encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Path) -> GazetteerRules:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            frozenset(data["common_words"]),
            frozenset((a, lab) for a, lab in data["blocklist"]),
            {(a, lab): new for a, lab, new in data.get("relabel", [])},
        )


class Gazetteer:
    """Longest-match dictionary tagger over the tokens of a sentence."""

    def __init__(
        self,
        catalog: Catalog,
        labels: Iterable[str] = GAZETTEER_LABELS,
        rules: GazetteerRules | None = None,
        min_chars: int = 3,
        variants: bool = True,
    ) -> None:
        self.catalog = catalog
        self.labels = tuple(labels)
        self.rules = rules or GazetteerRules()
        self.variants = variants
        self.index: dict[tuple[str, ...], list[_Entry]] = defaultdict(list)
        self.compact: dict[str, list[_Entry]] = defaultdict(list)
        kinds = [k for k, lab in LABEL_OF_KIND.items() if lab in self.labels]
        for obj in catalog.of_kind(*kinds):
            for i, name in enumerate(_expand(obj, catalog)):
                tokens = tuple(t.text for t in tokenize(name))
                if (
                    len(name) < min_chars
                    or name.isdigit()
                    or not 0 < len(tokens) <= MAX_ALIAS_TOKENS
                ):
                    continue
                entry = _Entry(obj, tokens, i == 0)
                self.index[tuple(_norm(t) for t in tokens)].append(entry)
                if obj.label in ENTITY_LABELS and len(_compact(name)) >= 4:
                    self.compact[_compact(name)].append(entry)
        for entries in (*self.index.values(), *self.compact.values()):
            entries.sort(key=_priority)

    # ------------------------------------------------------------------ matching

    def _label(self, entry: _Entry) -> str | None:
        """Label after the learned rules, or None if the pair is blocklisted."""
        key = (" ".join(_norm(t) for t in entry.tokens), entry.obj.label)
        if key in self.rules.blocklist:
            return None
        return self.rules.relabel.get(key, entry.obj.label)

    def _surface_ok(self, entry: _Entry, label: str, words: Sequence[str], start: int) -> bool:
        if label not in ENTITY_LABELS:
            return True
        if words[-1].lower().endswith(".exe"):
            return True  # psexec.exe, ping.exe: an executable name is unambiguous
        alias = " ".join(entry.tokens)
        if label != "TOOL" and alias != alias.lower() and all(w == w.lower() for w in words):
            return False  # "anchor" is not Anchor; "remcos" is a file name, not Remcos
        if all(_norm(t) in self.rules.common_words for t in entry.tokens):
            exact = tuple(_POSSESSIVE_RE.sub("", w) for w in words) == entry.tokens
            return exact and start > 0
        return True

    def _first(self, entries: Sequence[_Entry], words: Sequence[str], start: int) -> Mention | None:
        for entry in entries:
            label = self._label(entry)
            if label and self._surface_ok(entry, label, words, start):
                end = start + len(words)
                return Mention(start, end, label, entry.obj.attack_id, "gazetteer")
        return None

    def match(self, words: Sequence[str]) -> list[Mention]:
        """Non-overlapping, leftmost-longest matches over the tokens of one sentence."""
        normed = [_norm(w) for w in words]
        mentions = []
        i = 0
        while i < len(words):
            found = None
            for length in range(min(MAX_ALIAS_TOKENS, len(words) - i), 0, -1):
                entries = self.index.get(tuple(normed[i : i + length]))
                if entries and (found := self._first(entries, words[i : i + length], i)):
                    break
            if not found and self.variants:
                for length in (2, 1):
                    window = words[i : i + length]
                    if len(window) < length or not all(w[:1].isalnum() for w in window):
                        continue
                    for key in _variants("".join(window)):
                        if found := self._first(self.compact.get(key, ()), window, i):
                            break
                    if found:
                        break
            if found:
                mentions.append(found)
                i = found.end
            else:
                i += 1
        return mentions

    def link(self, surface: str, label: str | None = None) -> AttackObject | None:
        """ATT&CK object that a mention's text names, if any (exact alias, then variants)."""
        key = tuple(_norm(t.text) for t in tokenize(surface))
        candidates = list(self.index.get(key, []))
        for variant in _variants(surface):
            candidates += self.compact.get(variant, [])
        for entry in candidates:
            if label is None or self._label(entry) == label:
                return entry.obj
        return None


# --------------------------------------------------------------------------- rule learning


def common_words(
    corpus: Iterable[Sequence[str]], min_count: int = 3, min_share: float = 0.5
) -> frozenset[str]:
    """Words written in lower case at least ``min_share`` of the time and ``min_count`` times."""
    lower: Counter[str] = Counter()
    total: Counter[str] = Counter()
    for words in corpus:
        for w in words:
            if w.isalpha():
                total[w.casefold()] += 1
                if w.islower():
                    lower[w] += 1
    return frozenset(w for w, n in lower.items() if n >= min_count and n / total[w] >= min_share)


def fit_rules(
    catalog: Catalog,
    sentences: Sequence[tuple[Sequence[str], Sequence[str]]],
    reference_corpus: Iterable[Sequence[str]],
    min_matches: int = 3,
    max_precision: float = 0.2,
) -> GazetteerRules:
    """Learn common words, relabelling and blocklist from training (tokens, BIO tags) pairs."""
    words_rule = GazetteerRules(common_words(reference_corpus))
    gazetteer = Gazetteer(catalog, rules=words_rule)
    hits: Counter[tuple[str, str]] = Counter()
    gold_labels: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for words, tags in sentences:
        gold = {(s, e): lab for s, e, lab in bio_to_spans(tags)}
        for m in gazetteer.match(words):
            entry_key = _alias_key(gazetteer, words[m.start : m.end], m)
            hits[entry_key] += 1
            gold_labels[entry_key][gold.get((m.start, m.end), "O")] += 1
    relabel, blocklist = {}, set()
    for key, n in hits.items():
        label = key[1]
        best, best_n = gold_labels[key].most_common(1)[0]
        if best != label and best in GAZETTEER_LABELS and best_n / n >= 0.5 and n >= 2:
            relabel[key] = best
        elif n >= min_matches and gold_labels[key][label] / n < max_precision:
            blocklist.add(key)
    return GazetteerRules(words_rule.common_words, frozenset(blocklist), relabel)


def _alias_key(gazetteer: Gazetteer, words: Sequence[str], m: Mention) -> tuple[str, str]:
    """(normalised alias, ATT&CK label) of the entry that produced ``m``."""
    obj = gazetteer.catalog.objects[m.attack_id] if m.attack_id else None
    normed = tuple(_norm(w) for w in words)
    for entry in gazetteer.index.get(normed, []):
        if entry.obj is obj:
            return " ".join(normed), entry.obj.label
    for key in _variants("".join(words)):
        for entry in gazetteer.compact.get(key, []):
            if entry.obj is obj:
                return " ".join(_norm(t) for t in entry.tokens), entry.obj.label
    return " ".join(normed), m.label
