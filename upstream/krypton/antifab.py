"""Anti-fabrication detection.

Ported and adapted from the user's battle-tested ``keep-going.py`` Stop hook.
Krypton runs these checks on the worker's last message every turn; any hits are
fed to the manager, which confronts the worker and demands proof or retraction
(R15). Detection is conservative — it only flags claims that are *verifiable* and
*wrong*, and skips claims that are clearly being discussed/retracted.
"""
from __future__ import annotations

import re
from pathlib import Path

_EXT = r"(?:md|json|txt|log|html|py|sh|js|jsonl|yaml|yml|csv|xml|conf|toml|ini)"

PATH_RX = re.compile(
    r"(?<![\w/:])"
    r"((?:/(?:tmp|root|home|var|opt|etc|mnt|srv)|\./[A-Za-z0-9_.-]+|\.claude)"
    r"/[A-Za-z0-9._/-]+"
    r"\." + _EXT + r")"
    r"(?![\w/])"
)
LINE_COUNT_RX = re.compile(r"\((\d+)\s*lines?\)", re.IGNORECASE)
DIR_HINT_RX = re.compile(r"(/(?:tmp|root|home|var|opt|etc|mnt|srv)/[A-Za-z0-9._/-]+/)")

PATH_NEG_CTX = (
    "claimed", "fabricated", "fabrication", "fake", "missing", "absent",
    "doesn't exist", "does not exist", "never exists", "never existed",
    "earlier said", "previously said", "retracted", "invented", "made-up",
    "made up", "the agent ", "is not", "isn't", "no such", "no candidate",
    "non-existent", "nonexistent", "did not write", "didn't write",
    "no tool_use", "flagged", "bogus", "phantom", "imaginary", "didn't actually",
)


def _strip_for_paths(text: str) -> str:
    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    text = re.sub(r'"[^"]*"', "", text)
    return text


def _has_neg_ctx(text: str, start: int, end: int, window: int = 80) -> bool:
    ctx = text[max(0, start - window):min(len(text), end + window)].lower()
    return any(neg in ctx for neg in PATH_NEG_CTX)


def _lc_drift(p: Path, claimed: int):
    try:
        with p.open(errors="replace") as fh:
            real = sum(1 for _ in fh)
        if abs(claimed - real) > 5 and abs(claimed - real) > real * 0.2:
            return real
    except (OSError, ValueError):
        pass
    return None


def scan(last_text: str, cwd: Path | None = None, max_flags: int = 6) -> list[str]:
    """Return human-readable fabrication flags for the worker's last message."""
    if not last_text:
        return []
    flags: list[str] = []
    stripped = _strip_for_paths(last_text)
    seen: set[str] = set()

    for m in PATH_RX.finditer(stripped):
        path_str = m.group(1)
        if path_str in seen:
            continue
        seen.add(path_str)
        if _has_neg_ctx(stripped, m.start(), m.end()):
            continue
        try:
            p = Path(path_str)
            if not p.is_absolute() and cwd:
                p = cwd / path_str
            if not p.exists():
                flags.append(f"Claimed file does not exist on disk: {path_str}")
            else:
                ctx = stripped[max(0, m.start() - 20):m.end() + 60]
                lc = LINE_COUNT_RX.search(ctx)
                if lc:
                    real = _lc_drift(p, int(lc.group(1)))
                    if real is not None:
                        flags.append(
                            f"Line-count mismatch for {path_str}: claimed {lc.group(1)}, actual {real}")
        except (OSError, ValueError):
            pass
        if len(flags) >= max_flags:
            break
    return flags
