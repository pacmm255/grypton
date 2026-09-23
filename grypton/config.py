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
# Operator-supplied target credentials and authenticated session material live
# outside model-visible engagement workspaces. Only local credential tools
# resolve names from this directory; prompts and MCP arguments contain aliases.
CREDENTIALS_DIR = STATE_DIR / "credentials"
# OpenCode's project discovery walks above engagement directories even when
# Git's ceiling variables are set. Keep its tiny execution workspaces outside
# the Grypton source checkout while evidence stays under ENGAGEMENTS_DIR.
OPENCODE_WORKSPACES_DIR = Path(os.environ.get(
    "GRYPTON_OPENCODE_WORKSPACES_DIR",
    str(Path.home() / ".local/state/grypton/opencode-workspaces"),
)).resolve()
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
OPENCLAUDE_HOME = Path(os.environ.get("GRYPTON_OPENCLAUDE_HOME", "/root/openclaude")).resolve()
OPENCLAUDE_BIN = OPENCLAUDE_HOME / "bin" / "openclaude.mjs"


# --------------------------------------------------------------------------
# Exact requested model/provider/effort routes.
# --------------------------------------------------------------------------

WORKER_PROVIDER = os.environ.get("GRYPTON_WORKER_PROVIDER", "zai-coding-plan")
WORKER_MODEL = os.environ.get("GRYPTON_WORKER_MODEL", "zai-coding-plan/glm-5.3")
WORKER_EFFORT = os.environ.get("GRYPTON_WORKER_EFFORT", "max")
MANAGER_PROVIDER = os.environ.get("GRYPTON_MANAGER_PROVIDER", "go")
MANAGER_MODEL = os.environ.get(
    "GRYPTON_MANAGER_MODEL", "go/muse-spark-1.3-contributor")
MANAGER_EFFORT = os.environ.get("GRYPTON_MANAGER_EFFORT", "xhigh")
VALIDATOR_PROVIDER = "openai"
# Astra is an independent, fixed trust boundary. Unlike Kraude and Kryptex,
# its route and effort must not be changed by ambient environment variables or
# saved operator configuration.
VALIDATOR_MODEL = "gpt-6-astra"
VALIDATOR_EFFORT = "max"
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

MODEL_ROUTE_ALIASES = {
    "opencode-go/muse-spark-1.3-contributor": "go/muse-spark-1.3-contributor",
}


def normalize_model_route(name: str) -> str:
    """Return the public OpenClaude route for a configured model name."""
    route = str(name or "").strip()
    if not route:
        return ""
    route = MODEL_ROUTE_ALIASES.get(route, route)
    if route.startswith("opencode-go/"):
        return f"go/{route.removeprefix('opencode-go/')}"
    if route.startswith("opencode/"):
        return f"zen/{route.removeprefix('opencode/')}"
    return route


def resolve_manager_model(name: str) -> str:
    """Normalize legacy manager routes to OpenClaude public routes."""
    return normalize_model_route(name)


def resolve_worker_model(name: str) -> str:
    """Expand the supported GLM shortcut; qualified OpenCode routes pass through."""
    if not name:
        return ""
    return normalize_model_route(WORKER_MODEL_ALIASES.get(name.strip().lower(), name.strip()))


WORKER_MODEL = resolve_worker_model(WORKER_MODEL)
MANAGER_MODEL = resolve_manager_model(MANAGER_MODEL)

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

    # Non-stop doctrine (R1/R12). stop_on_p1=False => keep hunting even after a P1.
    stop_on_p1: bool = False
    # Hard ceilings purely as runaway safety nets. 0 = unbounded.
    max_run_seconds: int = 0
    max_turns: int = 0
    # How many consecutive "no new surface, no new finding" worker turns before
    # the manager is forced to escalate to a fresh expansion strategy.
    exhaustion_threshold: int = 2
    # Stop ledger churn from masquerading as research.  A repeated request
    # signature is allowed for controls, but it stops counting as novelty after
    # this many executions.  Kryptex gets one directed pivot after a convergence
    # threshold; another stagnant turn ends the run cleanly.
    probe_repeat_limit: int = 3
    repetitive_probe_turn_limit: int = 3
    passive_stagnation_limit: int = 6
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
        loaded = cls(**{k: v for k, v in data.items() if k in known})
        loaded.worker_model = resolve_worker_model(loaded.worker_model)
        loaded.manager_model = resolve_manager_model(loaded.manager_model)
        return loaded

    def save(self) -> None:
        """Write global defaults atomically with private permissions."""
        path = GRYPTON_HOME / "grypton.json"
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = path.with_suffix(path.suffix + ".tmp")
        fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(asdict(self), indent=2) + '\n')
        os.replace(tmp, path)


def effective_role_models(meta: object | None = None) -> dict[str, dict[str, str]]:
    """Return effective per-role routes and efforts, honoring workspace overrides."""

    def selected(field: str, fallback: str) -> str:
        value = getattr(meta, field, "") if meta is not None else ""
        return str(value or fallback)

    return {
        "worker": {
            "route": resolve_worker_model(selected("worker_model", CONFIG.worker_model)),
            "effort": selected("worker_effort", CONFIG.worker_effort),
        },
        "manager": {
            "route": resolve_manager_model(selected("manager_model", CONFIG.manager_model)),
            "effort": selected("manager_effort", CONFIG.manager_effort),
        },
        "validator": {
            "route": VALIDATOR_MODEL,
            "effort": VALIDATOR_EFFORT,
        },
    }


def ensure_layout() -> None:
    """Create Grypton's private runtime directories (idempotent)."""
    for d in (
        STATE_DIR, ENGAGEMENTS_DIR, RUNTIME_DIR, LOG_DIR, PROVIDER_DIR,
        CREDENTIALS_DIR, OPENCODE_WORKSPACES_DIR,
        TARGET_DATA_DIR,
    ):
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(d, 0o700)


# Convenience singletons (cheap; no I/O beyond an optional small file read).
CONFIG = GryptonConfig.load()
