"""Grypton global configuration, filesystem layout, and environment discovery.

Dependency-free (stdlib only) and side-effect-free at import time.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, urlsplit

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
SEVERITY_RUBRIC_PATH = RESOURCES_DIR / "severity_rubric.json"
BIN_DIR = (
    SOURCE_ROOT / "bin"
    if (SOURCE_ROOT / "bin").is_dir()
    else Path(sys.executable).parent
)
KRYPTON_HOME = GRYPTON_HOME                      # compatibility for restored modules
OPENCLAUDE_HOME = Path(os.environ.get("GRYPTON_OPENCLAUDE_HOME", "/root/openclaude")).resolve()
OPENCLAUDE_BIN = OPENCLAUDE_HOME / "bin" / "openclaude.mjs"

# The operator-facing proxy value stays in the supervising Grypton process.
# Tool subprocesses receive only a private Unix-socket rendezvous path so the
# proxy URL (including optional credentials) never enters provider state.
EGRESS_PROXY_ENV = "GRYPTON_EGRESS_PROXY"
PRIVATE_EGRESS_PROXY_SOCKET_ENV = "GRYPTON_PRIVATE_EGRESS_PROXY_SOCKET"
_MAX_EGRESS_PROXY_BYTES = 4096


def _proxy_from_private_socket(path: str) -> str:
    """Read one in-memory proxy value from the supervising process."""
    if (
        not path or len(path.encode("utf-8")) > 4096
        or "\x00" in path or not os.path.isabs(path)
    ):
        raise ValueError("Private egress proxy setting is unavailable.")
    request = b'{"operation":"egress_proxy"}\n'
    chunks: list[bytes] = []
    total = 0
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(path)
            connection.sendall(request)
            while True:
                block = connection.recv(4096)
                if not block:
                    break
                chunks.append(block)
                total += len(block)
                if total > (_MAX_EGRESS_PROXY_BYTES * 2) + 1024:
                    raise ValueError("Private egress proxy setting is unavailable.")
    except (OSError, ValueError) as exc:
        raise ValueError("Private egress proxy setting is unavailable.") from exc
    try:
        envelope = json.loads(b"".join(chunks))
        value = envelope.get("value") if envelope.get("ok") is True else None
    except (AttributeError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Private egress proxy setting is unavailable.") from exc
    if not isinstance(value, str):
        raise ValueError("Private egress proxy setting is unavailable.")
    return value


def private_egress_proxy(environ: Optional[dict[str, str]] = None) -> str:
    """Return a validated private HTTP(S) proxy without making it observable."""
    source = os.environ if environ is None else environ
    raw = str(source.get(EGRESS_PROXY_ENV) or "").strip()
    if not raw:
        socket_path = str(source.get(PRIVATE_EGRESS_PROXY_SOCKET_ENV) or "").strip()
        if socket_path:
            raw = _proxy_from_private_socket(socket_path).strip()
    if not raw:
        return ""
    if (
        len(raw.encode("utf-8")) > _MAX_EGRESS_PROXY_BYTES
        or any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7f for char in raw)
    ):
        raise ValueError("Private egress proxy setting is invalid.")
    try:
        parsed = urlsplit(raw)
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValueError("Private egress proxy setting is invalid.") from exc
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.query or parsed.fragment
        or parsed.path not in {"", "/"}
        or (parsed_port is not None and not 1 <= parsed_port <= 65535)
    ):
        raise ValueError("Private egress proxy setting is invalid.")
    return raw


def private_egress_proxy_redaction_values(proxy: str) -> tuple[str, ...]:
    """Return proxy forms that subprocess or provider diagnostics may echo."""
    raw = str(proxy or "")
    if not raw:
        return ()
    values = {raw}
    try:
        parsed = urlsplit(raw)
        if parsed.hostname:
            values.add(parsed.hostname)
            endpoint = (
                f"[{parsed.hostname}]" if ":" in parsed.hostname
                else parsed.hostname
            )
            if parsed.port is not None:
                endpoint += f":{parsed.port}"
            values.add(endpoint)
        if parsed.username is not None:
            values.add(unquote(parsed.username))
        if parsed.password is not None:
            values.add(unquote(parsed.password))
    except ValueError:
        pass
    return tuple(sorted((value for value in values if value), key=len, reverse=True))


# --------------------------------------------------------------------------
# Exact requested model/provider/effort routes.
# --------------------------------------------------------------------------

WORKER_PROVIDER = os.environ.get("GRYPTON_WORKER_PROVIDER", "go")
WORKER_MODEL = os.environ.get(
    "GRYPTON_WORKER_MODEL", "go/longcat-2.5-preview-free")
WORKER_EFFORT = os.environ.get("GRYPTON_WORKER_EFFORT", "on")
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
    """Expand supported shortcuts; qualified OpenClaude routes pass through."""
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
    # Optional Astra-confirmed stopping threshold. ``P2`` means P1 or P2;
    # an empty value preserves the legacy stop_on_p1 behavior.
    until_severity: str = ""
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
    # Start a new Kraude conversation after this many reported OpenCode tokens
    # have accumulated in one worker session. 0 disables automatic rollover.
    worker_context_rollover_tokens: int = 250_000

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
