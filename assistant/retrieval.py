"""Runbook search using TF-IDF vectors and cosine similarity, with no external dependencies."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

_TOKEN = re.compile(r"[a-z0-9]+")
MIN_SCORE = 0.05


def tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


@dataclass(frozen=True)
class Chunk:
    id: str
    runbook: str
    heading: str
    text: str


@dataclass(frozen=True)
class Hit:
    chunk: Chunk
    score: float


class RunbookIndex:
    def __init__(self, directory: Path) -> None:
        self.chunks = [chunk for path in sorted(directory.glob("*.md")) for chunk in _split(path)]
        if not self.chunks:
            raise ValueError(f"No runbooks found in {directory}")
        documents = [Counter(tokenize(f"{c.runbook} {c.heading} {c.text}")) for c in self.chunks]
        frequency = Counter(token for document in documents for token in document)
        count = len(documents)
        self._idf = {t: math.log((1 + count) / (1 + df)) + 1 for t, df in frequency.items()}
        self._vectors = [self._vector(document) for document in documents]

    def _vector(self, counts: Counter[str]) -> dict[str, float]:
        vector = {t: n * self._idf[t] for t, n in counts.items() if t in self._idf}
        norm = math.sqrt(sum(v * v for v in vector.values())) or 1.0
        return {t: v / norm for t, v in vector.items()}

    def search(self, query: str, limit: int = 3) -> list[Hit]:
        vector = self._vector(Counter(tokenize(query)))
        scored = (
            Hit(chunk, sum(w * doc.get(t, 0.0) for t, w in vector.items()))
            for chunk, doc in zip(self.chunks, self._vectors)
        )
        hits = [hit for hit in scored if hit.score >= MIN_SCORE]
        return sorted(hits, key=lambda hit: hit.score, reverse=True)[:limit]


def _split(path: Path) -> list[Chunk]:
    chunks: list[Chunk] = []
    for section in re.split(r"(?m)^## ", path.read_text(encoding="utf-8"))[1:]:
        heading, _, body = section.partition("\n")
        heading = heading.strip()
        chunks.append(Chunk(f"runbook:{path.stem}#{heading}", path.stem, heading, body.strip()))
    return chunks
