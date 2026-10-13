"""Tokenisation and sentence splitting with character offsets.

The tokeniser approximates the AnnoCTR tokenisation (the corpus the entity model is trained
on): words keep internal ``.``, ``-``, ``_``, ``'`` and ``@`` (``cmd.exe``, ``third-party``,
``victim's``) and every other non-space character is a token of its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_TOKEN_RE = re.compile(r"\w+(?:[.'’@-]\w+)*|\S")
_SENTENCE_END_RE = re.compile(r"(?<=[.!?])[\"”’)\]]*\s+(?=[\"“(\[]?[A-Z0-9])")
_ABBREVIATIONS = frozenset(
    {"e.g", "i.e", "etc", "vs", "fig", "no", "inc", "ltd", "corp", "co", "approx", "dr", "mr"}
    | {"mrs", "ms", "jr", "sr", "st", "u.s", "u.k", "cf", "al"}
)
# Lines that stand on their own: headings, list items, table rows, quotes, code fences.
_STRUCTURAL_RE = re.compile(r"\s*(?:#|[-*+] |\d+[.)] |\||>|```)")


@dataclass(frozen=True, slots=True)
class Token:
    text: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class Sentence:
    text: str
    start: int  # offset in the document
    tokens: tuple[Token, ...]  # offsets in the document

    @property
    def words(self) -> list[str]:
        return [t.text for t in self.tokens]


def tokenize(text: str, offset: int = 0) -> list[Token]:
    return [
        Token(m.group(), m.start() + offset, m.end() + offset) for m in _TOKEN_RE.finditer(text)
    ]


def split_sentences(text: str) -> list[Sentence]:
    """Paragraphs, then sentence-final punctuation followed by a capital.

    Hard-wrapped lines of a paragraph are joined, so a sentence broken over two lines stays
    one sentence; headings, list items and table rows are kept on their own. Abbreviations
    (``e.g.``, ``U.S.``) and initials do not end a sentence.
    """
    out = []
    for start, block in _blocks(text):
        out.extend(_split_line(block, start))
    return out


def _blocks(text: str) -> list[tuple[int, str]]:
    """(offset, text) of each paragraph or structural line; newlines inside are kept."""
    blocks: list[tuple[int, str]] = []
    run_start = run_end = None
    pos = 0
    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        if content.strip() and not _STRUCTURAL_RE.match(content):
            if run_start is None:
                run_start = pos
            run_end = pos + len(content)
        else:
            if run_start is not None:
                blocks.append((run_start, text[run_start:run_end]))
                run_start = None
            if content.strip():
                blocks.append((pos, content))
        pos += len(line)
    if run_start is not None:
        blocks.append((run_start, text[run_start:run_end]))
    return [(o + len(b) - len(b.lstrip()), b.strip()) for o, b in blocks]


def _split_line(line: str, offset: int) -> list[Sentence]:
    sentences = []
    start = 0
    for m in _SENTENCE_END_RE.finditer(line):
        before = line[start : m.start()].rsplit(None, 1)
        last_word = before[-1].rstrip(".!?").lower() if before else ""
        if last_word in _ABBREVIATIONS or (len(last_word) == 1 and last_word.isalpha()):
            continue
        sentences.append(_sentence(line[start : m.start()], offset + start))
        start = m.end()
    if start < len(line):
        sentences.append(_sentence(line[start:], offset + start))
    return [s for s in sentences if s.tokens]


def _sentence(text: str, offset: int) -> Sentence:
    text = text.rstrip()
    return Sentence(text, offset, tuple(tokenize(text, offset)))
