#!/usr/bin/env python3
"""Small local retrieval helper for the standalone NetOps AI layer."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

SCRIPT_PATH = Path(__file__).resolve()
AI_DIR = SCRIPT_PATH.parents[1]
NETOPS_ROOT = AI_DIR.parent
SOURCES_FILE = AI_DIR / "config" / "rag_sources.txt"
TEXT_SUFFIXES = {".md", ".py", ".sh", ".yaml", ".yml", ".txt", ".json", ".conf", ""}
SKIP_PARTS = {".git", "node_modules", "__pycache__", ".vite", "dist"}


def source_patterns() -> List[str]:
    if not SOURCES_FILE.exists():
        return []
    return [line.strip() for line in SOURCES_FILE.read_text(encoding="utf-8").splitlines() if line.strip() and not line.strip().startswith("#")]


def safe_path(path: Path) -> bool:
    try:
        resolved = path.resolve()
        resolved.relative_to(NETOPS_ROOT.resolve())
    except ValueError:
        return False
    return not any(part in SKIP_PARTS for part in resolved.parts)


def iter_files() -> Iterable[Path]:
    seen = set()
    for pattern in source_patterns():
        base_pattern = pattern.rstrip("/")
        candidates: Sequence[Path]
        if any(char in base_pattern for char in "*?[]"):
            candidates = list(NETOPS_ROOT.glob(base_pattern))
        else:
            candidates = [NETOPS_ROOT / base_pattern]
        for candidate in candidates:
            if candidate.is_dir():
                nested = candidate.rglob("*")
            else:
                nested = [candidate]
            for path in nested:
                if not path.is_file() or not safe_path(path):
                    continue
                if path.suffix not in TEXT_SUFFIXES:
                    continue
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                yield resolved


def terms(query: str) -> List[str]:
    return [term for term in re.findall(r"[a-z0-9_.:-]+", query.lower()) if len(term) > 1]


def line_score(line: str, wanted: Sequence[str]) -> int:
    lower = line.lower()
    return sum(lower.count(term) for term in wanted)


def snippets_for_file(path: Path, wanted: Sequence[str], context: int) -> List[Tuple[int, int, str]]:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    hits: List[Tuple[int, int, str]] = []
    for index, line in enumerate(lines):
        score = line_score(line, wanted)
        if score <= 0:
            continue
        start = max(0, index - context)
        end = min(len(lines), index + context + 1)
        snippet = "\n".join(lines[start:end]).strip()
        hits.append((score, index + 1, snippet))
    return hits


def search(query: str, limit: int, context: int) -> List[Dict[str, object]]:
    wanted = terms(query)
    if not wanted:
        return []
    results: List[Dict[str, object]] = []
    for path in iter_files():
        rel = path.relative_to(NETOPS_ROOT)
        guide_boost = 5 if str(rel).startswith("ai/docs/") else 0
        for score, line_no, snippet in snippets_for_file(path, wanted, context):
            results.append({"score": score + guide_boost, "path": str(rel), "line": line_no, "snippet": snippet})
    results.sort(key=lambda item: (-int(item["score"]), str(item["path"]), int(item["line"])))
    return results[:limit]


def main() -> int:
    parser = argparse.ArgumentParser(description="Search NetOps AI RAG source files")
    parser.add_argument("query", nargs="+", help="Search query")
    parser.add_argument("--limit", type=int, default=8)
    parser.add_argument("--context", type=int, default=2)
    args = parser.parse_args()
    query = " ".join(args.query)
    results = search(query, max(1, args.limit), max(0, args.context))
    if not results:
        print("No matching source snippets found.")
        return 1
    for item in results:
        print(f"{item['path']}:{item['line']} score={item['score']}")
        print(item["snippet"])
        print("---")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
