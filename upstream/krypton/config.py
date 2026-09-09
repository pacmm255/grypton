"""Krypton global configuration, filesystem layout, and environment discovery.

Dependency-free (stdlib only) and side-effect-free at import time — every other
Krypton module imports this, so it must stay light and never throw on import.
"""
from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------
# Repository / Krypton home layout
# --------------------------------------------------------------------------

KRYPTON_HOME = Path(
    os.environ.get("KRYPTON_HOME", Path(__file__).resolve().parent.parent)
).resolve()

TARGETS_DIR = KRYPTON_HOME / "targets"          # per-target workspaces
SESSIONS_DIR = KRYPTON_HOME / "sessions"        # session snapshots
INIT0_DIR = SESSIONS_DIR / "init0"              # frozen, immutable Init 0 snapshot
RUNTIME_DIR = KRYPTON_HOME / ".runtime"         # pidfiles, transient run state
LOG_DIR = RUNTIME_DIR / "logs"
PROMPTS_DIR = KRYPTON_HOME / "prompts"
BIN_DIR = KRYPTON_HOME / "bin"

# --------------------------------------------------------------------------
# Claude Code ("kraude" worker) layout
# --------------------------------------------------------------------------

CLAUDE_HOME = Path(
    os.environ.get("CLAUDE_CONFIG_DIR", Path.home() / ".claude")
).resolve()
CLAUDE_PROJECTS_DIR = CLAUDE_HOME / "projects"

# The user's live, pre-trained session that becomes Init 0. Resolved by search
# term (the same string the user passes to `claude --resume`).
DEFAULT_INIT0_RESUME_TERM = os.environ.get(
    "KRYPTON_INIT0_SESSION", "bitpanda-graphql-security-assessment"
)

# --------------------------------------------------------------------------
# Codex ("kryptex" manager) layout
# --------------------------------------------------------------------------

CODEX_HOME = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")).resolve()

# --------------------------------------------------------------------------
# Models / effort — the "kraude" worker defaults to Sonnet 5 @ high effort.
# NOTE (measured 2026-07-04): Sonnet 5 and Opus 4.8 BOTH run with a 1M-token
# context window here; the model choice does NOT change the window, and the
# Claude Code "[1m]" suffix is a no-op for Sonnet 5. If the worker idles with a
# synthetic "Prompt is too long", the cause is the resumed Init-0 seed exceeding
# 1M tokens (see sessions/init0) — NOT this model setting; it would fail on Opus
# too. Fix the seed size, not the model.
# Editable INSIDE by changing these two constants; OUTSIDE via the env vars
# KRYPTON_WORKER_MODEL / KRYPTON_WORKER_EFFORT or the CLI --model/--worker-model
# flag (model names resolved through WORKER_MODEL_ALIASES below). Manager is
# codex default.
# --------------------------------------------------------------------------

WORKER_MODEL = os.environ.get("KRYPTON_WORKER_MODEL", "claude-sonnet-5")
WORKER_EFFORT = os.environ.get("KRYPTON_WORKER_EFFORT", "high")
# Empty manager model => use whatever ~/.codex/config.toml selects (gpt-5.5).
MANAGER_MODEL = os.environ.get("KRYPTON_MANAGER_MODEL", "")
MANAGER_EFFORT = os.environ.get("KRYPTON_MANAGER_EFFORT", "xhigh")

# CLI mode: force Kryptex's manager, validation, and worker lanes onto Codex
# 5.5 at the highest reasoning effort this install uses.
FULL_CODEX_MODEL = os.environ.get("KRYPTON_FULL_CODEX_MODEL", "gpt-5.5")
FULL_CODEX_EFFORT = os.environ.get("KRYPTON_FULL_CODEX_EFFORT", "xhigh")

# Which model drives the manager turn.
#   "codex"   — Kryptex on Codex (default). Claude is the fallback when Codex
#               errors or trips the content-policy filter.
#   "claude"  — Kryptex on Claude (Sonnet/Opus). Direct + chat skip Codex
#               entirely. Codex is used ONLY for severity validation
#               (validate_severity); if Codex is unavailable, Claude validates.
MANAGER_KIND = os.environ.get("KRYPTON_MANAGER_KIND", "codex").strip().lower() or "codex"

# Friendly worker-model aliases users can pass on the CLI (`--worker-model
# sonnet`). Empty string passes through unchanged.
WORKER_MODEL_ALIASES = {
    "opus":     "claude-opus-4-8",
    "opus48":   "claude-opus-4-8",
    "opus47":   "claude-opus-4-7",
    "sonnet":   "claude-sonnet-5",
    "sonnet5":  "claude-sonnet-5",
    "sonnet46": "claude-sonnet-4-6",
    "haiku":    "claude-haiku-4-5-20251001",
}


def resolve_worker_model(name: str) -> str:
    """Expand `sonnet`/`opus`/`haiku` shortcuts. Unknown names pass through so
    a literal `claude-sonnet-4-6` (or any other id) still works."""
    if not name:
        return ""
    return WORKER_MODEL_ALIASES.get(name.strip().lower(), name.strip())


# Let the OUTSIDE env knob accept the same shortcuts as the CLI, so
# `KRYPTON_WORKER_MODEL=sonnet5` (or `sonnet` / `opus` / …) expands to a full
# model id instead of being passed to Claude Code verbatim.
WORKER_MODEL = resolve_worker_model(WORKER_MODEL)

# --------------------------------------------------------------------------
# External tools
# --------------------------------------------------------------------------

GOJA_DIR = Path(os.environ.get("KRYPTON_GOJA_DIR", "/root/Goja")).resolve()
GOJA_SOCKS = os.environ.get("KRYPTON_GOJA_SOCKS", "127.0.0.1:1080")
GOJA_DASHBOARD = os.environ.get("KRYPTON_GOJA_DASHBOARD", "127.0.0.1:8034")

# --------------------------------------------------------------------------
# Path encoding helpers
# --------------------------------------------------------------------------


def encode_project_dir(path: os.PathLike | str) -> str:
    """Encode an absolute cwd to Claude Code's project-dir name.

    Claude maps a working directory to ``~/.claude/projects/<name>`` by replacing
    every non-alphanumeric character with ``-`` (verified against existing dirs:
    ``/root`` -> ``-root``, ``/root/krypton`` -> ``-root-krypton``). Runs are NOT
    collapsed, so ``/a/.b`` -> ``-a--b``.
    """
    resolved = str(Path(path).resolve())
    return re.sub(r"[^A-Za-z0-9]", "-", resolved)


def slugify(name: str) -> str:
    """Filesystem- and project-dir-safe slug (lowercase, ``[a-z0-9-]`` only)."""
    s = re.sub(r"[^a-zA-Z0-9]+", "-", str(name).strip().lower()).strip("-")
    return s or "target"


def project_dir_for(cwd: os.PathLike | str) -> Path:
    return CLAUDE_PROJECTS_DIR / encode_project_dir(cwd)


# --------------------------------------------------------------------------
# Binary discovery
# --------------------------------------------------------------------------

_BINARY_HINTS = {
    "claude": ["/root/.local/bin/claude"],
    "codex": [],
    "go": ["/usr/local/go/bin/go", "/root/go/bin/go"],
    "httpx": ["/root/go/bin/httpx", "/usr/local/bin/httpx"],
    "mitmdump": [],
    "chromium": ["/usr/bin/chromium", "/usr/bin/chromium-browser"],
}


def find_binary(name: str) -> Optional[str]:
    """Locate an executable on PATH or via known install hints."""
    found = shutil.which(name)
    if found:
        return found
    for hint in _BINARY_HINTS.get(name, []):
        if Path(hint).exists() and os.access(hint, os.X_OK):
            return hint
    return None


def require_binary(name: str) -> str:
    path = find_binary(name)
    if not path:
        raise FileNotFoundError(
            f"Required executable '{name}' not found on PATH. "
            f"Install it (Krypton can: `krypton doctor`) or set its location."
        )
    return path


# --------------------------------------------------------------------------
# Per-run / global Krypton configuration
# --------------------------------------------------------------------------


@dataclass
class KryptonConfig:
    """Tunable knobs. Loaded from ``KRYPTON_HOME/krypton.json`` if present;
    every field has a safe default so the file is optional."""

    worker_model: str = WORKER_MODEL
    worker_effort: str = WORKER_EFFORT
    manager_model: str = MANAGER_MODEL
    manager_effort: str = MANAGER_EFFORT

    # Non-stop doctrine (R1/R12). stop_on_p1=False => keep hunting even after a P1.
    stop_on_p1: bool = False
    # Hard ceilings purely as runaway safety nets. 0 = unbounded.
    max_run_seconds: int = 0
    max_turns: int = 0
    # How many consecutive "no new surface, no new finding" worker turns before
    # the manager is forced to escalate to a fresh expansion strategy.
    exhaustion_threshold: int = 2
    # Cap on transcript chars fed to the manager per turn (keeps codex fast).
    digest_char_budget: int = 24000

    # Tooling toggles
    enable_goja: bool = True
    enable_browser: bool = True
    enable_proxy_capture: bool = True

    # Backend selection: "real" drives claude+codex; "mock" uses bundled
    # deterministic emulators for offline end-to-end tests.
    backend: str = "real"

    @classmethod
    def load(cls) -> "KryptonConfig":
        path = KRYPTON_HOME / "krypton.json"
        data = {}
        if path.exists():
            try:
                data = json.loads(path.read_text())
            except (OSError, ValueError):
                data = {}
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})

    def save(self) -> None:
        (KRYPTON_HOME / "krypton.json").write_text(json.dumps(asdict(self), indent=2))


def ensure_layout() -> None:
    """Create the Krypton runtime directories (idempotent)."""
    for d in (TARGETS_DIR, SESSIONS_DIR, RUNTIME_DIR, LOG_DIR):
        d.mkdir(parents=True, exist_ok=True)


# Convenience singletons (cheap; no I/O beyond an optional small file read).
CONFIG = KryptonConfig.load()
