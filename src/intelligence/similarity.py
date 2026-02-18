"""Code similarity utilities for intelligence pattern matching.

Provides tokenization, normalization, and cosine-similarity for comparing
code diffs and PR embeddings stored as float32 blobs.
"""

from __future__ import annotations

import re

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


def cosine_similarity(a: bytes, b: bytes) -> float:
    """Compute cosine similarity between two float32 blob vectors.

    Returns 0.0 for zero-norm vectors, mismatched sizes, or invalid blobs.
    """
    # Fix #8: Guard against mismatched sizes and non-float32-aligned blobs
    if len(a) != len(b) or len(a) == 0 or len(a) % 4 != 0:
        return 0.0

    import numpy as np  # noqa: PLC0415

    va = np.frombuffer(a, dtype=np.float32)
    vb = np.frombuffer(b, dtype=np.float32)

    norm_a = np.linalg.norm(va)
    norm_b = np.linalg.norm(vb)
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0

    return float(np.dot(va, vb) / (norm_a * norm_b))


def vector_to_blob(vec: list[float]) -> bytes:
    """Serialize a float vector to a SQLite-storable bytes blob."""
    import numpy as np  # noqa: PLC0415

    return np.array(vec, dtype=np.float32).tobytes()


def blob_to_vector(blob: bytes) -> list[float]:
    """Deserialize a float32 blob back into a Python list."""
    import numpy as np  # noqa: PLC0415

    return np.frombuffer(blob, dtype=np.float32).tolist()
