"""Language registry — maps file extensions to tree-sitter parsers."""

from __future__ import annotations

import os
from functools import lru_cache

from tree_sitter import Language, Parser

# Section 3.3.1: extension → language mapping (Python + JS/TS for now)
EXTENSION_MAP: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
}

SUPPORTED_LANGUAGES = frozenset({"python", "javascript", "typescript", "tsx"})


def detect_language(filename: str) -> str | None:
    """Detect language from file extension.  Returns *None* for unsupported files."""
    ext = os.path.splitext(filename)[1].lower()
    return EXTENSION_MAP.get(ext)


@lru_cache(maxsize=None)
def _get_language_obj(name: str) -> Language:
    """Load a tree-sitter ``Language`` by canonical name (cached)."""
    if name == "python":
        import tree_sitter_python as _ts

        return Language(_ts.language())
    if name == "javascript":
        import tree_sitter_javascript as _ts

        return Language(_ts.language())
    if name == "typescript":
        import tree_sitter_typescript as _ts

        return Language(_ts.language_typescript())
    if name == "tsx":
        import tree_sitter_typescript as _ts

        return Language(_ts.language_tsx())
    raise ValueError(f"Unsupported language: {name}")


def get_parser(language_name: str) -> Parser:
    """Create a fresh ``Parser`` for the given language."""
    return Parser(_get_language_obj(language_name))
