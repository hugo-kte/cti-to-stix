"""Pinned public datasets: download with checksum verification, and loaders.

``datasets.toml`` names each source (GitHub repository, commit, remote folder, license) and
``checksums.sha256`` lists every file with its SHA-256, relative to ``data/raw/``. The first
path component selects the source: ``annoctr/ner_json/test.json`` is fetched from
``<repo>/<commit>/AnnoCTR/ner_json/test.json``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import tomllib
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

RAW = Path("data/raw")
MANIFEST = Path("datasets.toml")
CHECKSUMS = Path("checksums.sha256")
ATTACK_BUNDLE = "attack/enterprise-attack-19.2.json"
ANNOCTR_SPLITS = ("train", "dev", "test")


@dataclass(frozen=True, slots=True)
class Source:
    name: str
    repo: str
    commit: str
    remote: str
    license: str

    def url(self, relpath: str) -> str:
        """Raw URL of ``relpath`` (a path under data/raw/ starting with the source name)."""
        inner = relpath.split("/", 1)[1]
        return f"https://raw.githubusercontent.com/{self.repo}/{self.commit}/{self.remote}/{inner}"


def load_sources(manifest: Path = MANIFEST) -> dict[str, Source]:
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    return {
        name: Source(name, s["repo"], s["commit"], s["remote"], s["license"])
        for name, s in data["sources"].items()
    }


def read_checksums(path: Path = CHECKSUMS) -> list[tuple[str, str]]:
    """(sha256, relative path) pairs, in the ``sha256sum`` format."""
    pairs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            digest, rel = line.split(maxsplit=1)
            pairs.append((digest, rel.strip()))
    return pairs


def sha256(path: Path) -> str:
    with path.open("rb") as fh:
        return hashlib.file_digest(fh, "sha256").hexdigest()


def _fetch(url: str, dest: Path, retries: int = 3) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(url, timeout=60) as resp, tmp.open("wb") as fh:
                while chunk := resp.read(1 << 20):
                    fh.write(chunk)
            tmp.replace(dest)
            return
        except OSError as exc:
            if attempt == retries:
                raise
            log.warning("download failed (%s), retrying: %s", exc, url)
            time.sleep(2 * attempt)


def download(
    raw: Path = RAW, manifest: Path = MANIFEST, checksums: Path = CHECKSUMS, force: bool = False
) -> dict[str, int]:
    """Fetch every listed file that is missing or corrupt; raise if a checksum mismatches."""
    sources = load_sources(manifest)
    counts = {"present": 0, "downloaded": 0}
    for digest, rel in read_checksums(checksums):
        dest = raw / rel
        if dest.exists() and not force and sha256(dest) == digest:
            counts["present"] += 1
            continue
        source = sources[rel.split("/", 1)[0]]
        log.info("fetching %s", rel)
        _fetch(source.url(rel), dest)
        if (actual := sha256(dest)) != digest:
            raise ValueError(f"checksum mismatch for {rel}: expected {digest}, got {actual}")
        counts["downloaded"] += 1
    return counts


def verify(raw: Path = RAW, checksums: Path = CHECKSUMS) -> list[str]:
    """Relative paths that are missing or do not match their checksum."""
    return [rel for digest, rel in read_checksums(checksums) if not _ok(raw / rel, digest)]


def _ok(path: Path, digest: str) -> bool:
    return path.exists() and sha256(path) == digest


# --------------------------------------------------------------------------- loaders


@dataclass(frozen=True, slots=True)
class TramSentence:
    text: str
    labels: tuple[str, ...]
    doc: str


def load_tram(raw: Path = RAW) -> list[TramSentence]:
    """TRAM multi-label sentences, unlabelled ones included (they are the negatives)."""
    rows = json.loads((raw / "tram" / "multi_label.json").read_text(encoding="utf-8"))
    return [
        TramSentence(r["sentence"], tuple(sorted(set(r["labels"]))), r["doc_title"]) for r in rows
    ]


@dataclass(frozen=True, slots=True)
class NerSentence:
    id: str
    doc: str
    tokens: tuple[str, ...]
    tags: tuple[str, ...]  # BIO tags of the flat ``all_tags`` layer


def load_annoctr_ner(split: str, raw: Path = RAW) -> list[NerSentence]:
    """AnnoCTR sentences in the official split, with the flat (``all_tags``) BIO layer."""
    out = []
    for row in _jsonl(raw / "annoctr" / "ner_json" / f"{split}.json"):
        out.append(
            NerSentence(
                row["id"],
                row["id"].rsplit("__s", 1)[0],
                tuple(row["tokens"]),
                tuple(row["all_tags"]),
            )
        )
    return out


def load_annoctr_links(split: str, raw: Path = RAW) -> list[dict]:
    """AnnoCTR mentions linked to MITRE ATT&CK (KILT-style records)."""
    return list(_jsonl(raw / "annoctr" / "linking_mitre_only" / f"{split}.jsonl"))


def annoctr_texts(split: str, raw: Path = RAW) -> dict[str, str]:
    """Plain text of every AnnoCTR report in ``split`` (document id -> text)."""
    folder = raw / "annoctr" / "text" / split
    return {p.stem: p.read_text(encoding="utf-8") for p in sorted(folder.glob("*.txt"))}


def _jsonl(path: Path) -> Iterator[dict]:
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)
