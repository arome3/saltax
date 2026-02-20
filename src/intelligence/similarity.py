"""Code similarity utilities for intelligence pattern matching.

Provides tokenization, normalization, and cosine-similarity for comparing
code diffs and PR embeddings stored as float32 blobs.
"""

from __future__ import annotations

import re

import numpy as np

# ── Constants ────────────────────────────────────────────────────────────────

_MAX_PATTERN_LEN = 1000
_CODE_TOKEN_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")
_STRING_LITERAL_RE = re.compile(r"""(["'])(?:(?!\1).)*\1""")
_NUMERIC_LITERAL_RE = re.compile(r"\b\d+(?:\.\d+)?\b")
_WHITESPACE_RE = re.compile(r"\s+")

_STOPWORDS = frozenset({
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "shall", "can", "need", "dare", "ought",
    "if", "else", "elif", "for", "while", "in", "of", "to", "from",
    "import", "return", "def", "class", "self", "and", "or", "not",
    "true", "false", "none", "pass", "break", "continue", "with", "as",
    "try", "except", "finally", "raise", "assert", "yield", "lambda",
})


# ── Public API ───────────────────────────────────────────────────────────────


def _extract_code_tokens(text: str) -> list[str]:
    """Tokenize a code diff, filter stopwords, sort longest-first.

    Longer tokens produce more specific LIKE matches in SQL queries.
    """
    raw = _CODE_TOKEN_RE.findall(text)
    seen: set[str] = set()
    tokens: list[str] = []
    for tok in raw:
        lower = tok.lower()
        if lower not in _STOPWORDS and lower not in seen and len(lower) > 1:
            seen.add(lower)
            tokens.append(lower)
    tokens.sort(key=len, reverse=True)
    return tokens


def _normalize_pattern(snippet: str) -> str:
    """Normalize a code snippet for pattern matching.

    - Lowercase
    - Replace string literals with ``""``
    - Replace numeric literals with ``N``
    - Collapse whitespace
    - Truncate to 1000 chars (per doc 12 spec)
    """
    result = snippet.lower()
    result = _STRING_LITERAL_RE.sub('""', result)
    result = _NUMERIC_LITERAL_RE.sub("N", result)
    result = _WHITESPACE_RE.sub(" ", result).strip()
    return result[:_MAX_PATTERN_LEN]


def cosine_similarity_vectors(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity between two numpy vectors.

    Raises ``ValueError`` on dimension mismatch.
    Returns ``0.0`` for zero-norm or NaN-containing vectors.
    """
    if a.shape != b.shape:
        raise ValueError(
            f"Dimension mismatch: {a.shape} vs {b.shape}"
        )
    if np.isnan(a).any() or np.isnan(b).any():
        return 0.0
    norm_a = float(np.linalg.norm(a))
    norm_b = float(np.linalg.norm(b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))


def cosine_similarity(a: bytes, b: bytes) -> float:
    """Compute cosine similarity between two float32 blob vectors.

    Returns 0.0 for zero-norm vectors, mismatched sizes, or invalid blobs.
    """
    if len(a) != len(b) or len(a) == 0 or len(a) % 4 != 0:
        return 0.0

    va = np.frombuffer(a, dtype=np.float32)
    vb = np.frombuffer(b, dtype=np.float32)
    try:
        return cosine_similarity_vectors(va, vb)
    except ValueError:
        return 0.0


def ndarray_to_blob(vec: np.ndarray) -> bytes:
    """Serialize a numpy vector to a float32 bytes blob."""
    return vec.astype(np.float32).tobytes()


def blob_to_ndarray(blob: bytes) -> np.ndarray:
    """Deserialize a float32 bytes blob to a writable numpy array."""
    return np.frombuffer(blob, dtype=np.float32).copy()


def vector_to_blob(vec: list[float]) -> bytes:
    """Serialize a float list to a SQLite-storable bytes blob."""
    return np.array(vec, dtype=np.float32).tobytes()


def blob_to_vector(blob: bytes) -> list[float]:
    """Deserialize a float32 blob back into a Python float list."""
    return np.frombuffer(blob, dtype=np.float32).tolist()
