"""Grypton global configuration, filesystem layout, and environment discovery.

Dependency-free (stdlib only) and side-effect-free at import time.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------
# Repository / Grypton home layout
# --------------------------------------------------------------------------

PACKAGE_DIR = Path(__file__).resolve().parent
SOURCE_ROOT = PACKAGE_DIR.parent
_DEFAULT_HOME = (
    SOURCE_ROOT
    if (SOURCE_ROOT / "pyproject.toml").is_file()
    else Path.home() / ".local" / "share" / "grypton"
)
GRYPTON_HOME = Path(
    os.environ.get("GRYPTON_HOME", os.environ.get(
        "KRYPTON_HOME", _DEFAULT_HOME))
).resolve()

# Keep the requested top-level ``target/`` directory empty. Runtime engagement
# state lives under .state and never touches the excluded upstream targets data.
STATE_DIR = GRYPTON_HOME / ".state"
ENGAGEMENTS_DIR = STATE_DIR / "engagements"
TARGETS_DIR = ENGAGEMENTS_DIR                    # compatibility alias for core modules
RUNTIME_DIR = STATE_DIR / "runtime"
LOG_DIR = RUNTIME_DIR / "logs"
PROVIDER_DIR = STATE_DIR / "providers"
TARGET_DATA_DIR = GRYPTON_HOME / "target"
RESOURCES_DIR = PACKAGE_DIR / "resources"
PROMPTS_DIR = RESOURCES_DIR / "prompts"
SKILLS_DIR = RESOURCES_DIR / "skills"
SCENARIOS_PATH = RESOURCES_DIR / "autonomous_scenarios.json"
BIN_DIR = (
    SOURCE_ROOT / "bin"
    if (SOURCE_ROOT / "bin").is_dir()
    else Path(sys.executable).parent
)
KRYPTON_HOME = GRYPTON_HOME                      # compatibility for restored modules

# --------------------------------------------------------------------------
# Exact requested model/provider/effort routes.
# --------------------------------------------------------------------------

WORKER_PROVIDER = os.environ.get("GRYPTON_WORKER_PROVIDER", "zai-coding-plan")
WORKER_MODEL = os.environ.get("GRYPTON_WORKER_MODEL", "zai-coding-plan/glm-5.3")
WORKER_EFFORT = os.environ.get("GRYPTON_WORKER_EFFORT", "max")
MANAGER_PROVIDER = os.environ.get("GRYPTON_MANAGER_PROVIDER", "opencode-go")
MANAGER_MODEL = os.environ.get(
    "GRYPTON_MANAGER_MODEL", "opencode-go/muse-spark-1.3-contributor")
MANAGER_EFFORT = os.environ.get("GRYPTON_MANAGER_EFFORT", "xhigh")
VALIDATOR_PROVIDER = "openai"
VALIDATOR_MODEL = os.environ.get("GRYPTON_VALIDATOR_MODEL", "gpt-6-astra")
VALIDATOR_EFFORT = os.environ.get("GRYPTON_VALIDATOR_EFFORT", "max")
MANAGER_KIND = "opencode"
ASTRA_AUTO_SEVERITIES = frozenset({"P1", "P2"})


def astra_auto_validation_required(severity: str) -> bool:
    """Return whether a claimed severity requires automatic Astra review."""
    return str(severity or "").strip().upper() in ASTRA_AUTO_SEVERITIES

WORKER_MODEL_ALIASES = {
    "glm": "zai-coding-plan/glm-5.3",
    "glm5.3": "zai-coding-plan/glm-5.3",
    "glm-5.3": "zai-coding-plan/glm-5.3",
}


def resolve_worker_model(name: str) -> str:
    """Expand the supported GLM shortcut; qualified OpenCode routes pass through."""
    if not name:
        return ""
    return WORKER_MODEL_ALIASES.get(name.strip().lower(), name.strip())


WORKER_MODEL = resolve_worker_model(WORKER_MODEL)

# --------------------------------------------------------------------------
# External tools
# --------------------------------------------------------------------------

GOJA_DIR = Path(os.environ.get("GRYPTON_GOJA_DIR", "/root/Goja")).resolve()
GOJA_SOCKS = os.environ.get("GRYPTON_GOJA_SOCKS", "127.0.0.1:1080")
GOJA_DASHBOARD = os.environ.get("GRYPTON_GOJA_DASHBOARD", "127.0.0.1:8034")

# --------------------------------------------------------------------------
# Workspace naming
# --------------------------------------------------------------------------


def slugify(name: str) -> str:
    """Filesystem- and project-dir-safe slug (lowercase, ``[a-z0-9-]`` only)."""
    s = re.sub(r"[^a-zA-Z0-9]+", "-", str(name).strip().lower()).strip("-")
    return s or "target"


# --------------------------------------------------------------------------
# Binary discovery
# --------------------------------------------------------------------------

_BINARY_HINTS = {
    "opencode": [],
    "codex": [],
    "curl": ["/usr/bin/curl"],
    "go": ["/usr/local/go/bin/go", "/root/go/bin/go"],
    "httpx": ["/root/go/bin/httpx", "/usr/local/bin/httpx"],
    "mitmdump": [],
    "chromium": ["/usr/bin/chromium", "/usr/bin/chromium-browser"],
    "google-chrome": ["/usr/bin/google-chrome", "/opt/google/chrome/google-chrome"],
    "google-chrome-stable": ["/usr/bin/google-chrome-stable"],
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
            f"Install it (Grypton can: `grypton doctor`) or set its location."
        )
    return path


# --------------------------------------------------------------------------
# Per-run / global Grypton configuration
# --------------------------------------------------------------------------


@dataclass
class GryptonConfig:
    """Tunable knobs. Loaded from ``GRYPTON_HOME/grypton.json`` if present;
    every field has a safe default so the file is optional."""

    worker_model: str = WORKER_MODEL
    worker_effort: str = WORKER_EFFORT
    manager_model: str = MANAGER_MODEL
    manager_effort: str = MANAGER_EFFORT
    validator_model: str = VALIDATOR_MODEL
    validator_effort: str = VALIDATOR_EFFORT

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

    # Backend selection: "real" drives OpenCode+Codex; "mock" uses bundled
    # deterministic emulators for offline end-to-end tests.
    backend: str = "real"

    @classmethod
    def load(cls) -> "GryptonConfig":
        path = GRYPTON_HOME / "grypton.json"
        data = {}
        if path.exists():
            try:
                data = json.loads(path.read_text())
            except (OSError, ValueError):
                data = {}
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})

    def save(self) -> None:
        (GRYPTON_HOME / "grypton.json").write_text(json.dumps(asdict(self), indent=2))


def ensure_layout() -> None:
    """Create Grypton's private runtime directories (idempotent)."""
    for d in (
        STATE_DIR, ENGAGEMENTS_DIR, RUNTIME_DIR, LOG_DIR, PROVIDER_DIR,
        TARGET_DATA_DIR,
    ):
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(d, 0o700)


# Convenience singletons (cheap; no I/O beyond an optional small file read).
CONFIG = GryptonConfig.load()
