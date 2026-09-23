"""Private OpenClaude gateway adapter for Grypton's OpenCode transports.

The adapter owns one long-lived Node sidecar.  The sidecar imports OpenClaude's
documented module surface, discovers its sanitized model catalog, and starts an
authenticated loopback Messages gateway.  Provider API keys never cross the
stdio boundary.  The gateway token is inherited privately and is redacted from
representations, errors, and sidecar protocol output.
"""
from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field, replace
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
from typing import Any, Callable, Mapping, Optional


TOKEN_ENV = "GRYPTON_OPENCLAUDE_GATEWAY_TOKEN"
DEFAULT_OPENCLAUDE_ROOT = Path("/root/openclaude")
_PROTOCOL_VERSION = 1
_MAX_PROTOCOL_BYTES = 32 * 1024 * 1024
_ROUTE_ALIASES = {
    "opencode-go/": "go/",
    "opencode/": "zen/",
}
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ENV_REFERENCE = re.compile(r"^\{env:([A-Za-z_][A-Za-z0-9_]*)\}$")
_MAX_CONFIG_BYTES = 2 * 1024 * 1024

# OpenClaude needs ordinary process context plus the locations of its own and
# OpenCode's state. Provider secrets are added separately, and only when an
# active local configuration explicitly names their environment variable.
_PROCESS_ENV = (
    "HOME", "USER", "LOGNAME", "SHELL", "PATH", "TMPDIR", "LANG",
    "LC_ALL", "LC_CTYPE", "TZ", "TERM", "COLORTERM", "SSL_CERT_FILE",
    "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
)
_OPENCLAUDE_STATE_ENV = (
    "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
    "OPENCLAUDE_AUTH_FILE", "OPENCLAUDE_PRIVATE_STORE",
    "OPENCLAUDE_ANTHROPIC_AUTH", "OPENCLAUDE_CLAUDE_CONFIG_DIR",
    "OPENCLAUDE_CLAUDE_BIN", "OPENCLAUDE_OPENCODE_BIN", "CLAUDE_CONFIG_DIR",
    "CODEX_HOME", "OPENCODE_CONFIG", "OPENCODE_CONFIG_DIR",
    "OPENCODE_CONFIG_CONTENT",
)


class OpenClaudeError(RuntimeError):
    """OpenClaude discovery, sidecar, or gateway failure."""


def _clean(value: object, limit: int = 2000) -> str:
    text = _CONTROL.sub("", str(value or ""))
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]", text)
    text = re.sub(r"\bsk-[A-Za-z0-9_-]{12,}\b", "[REDACTED]", text)
    return text if len(text) <= limit else text[:limit] + "…"


def _parse_jsonc(source: str) -> dict[str, Any]:
    """Parse the JSON-with-comments subset used by OpenCode configuration."""
    clean: list[str] = []
    quoted = escaped = line_comment = block_comment = False
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if line_comment:
            clean.append("\n" if char == "\n" else " ")
            line_comment = char != "\n"
        elif block_comment:
            if char == "*" and following == "/":
                clean.extend((" ", " "))
                block_comment = False
                index += 1
            else:
                clean.append("\n" if char == "\n" else " ")
        elif quoted:
            clean.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
            clean.append(char)
        elif char == "/" and following == "/":
            clean.extend((" ", " "))
            line_comment = True
            index += 1
        elif char == "/" and following == "*":
            clean.extend((" ", " "))
            block_comment = True
            index += 1
        else:
            clean.append(char)
        index += 1
    if block_comment or quoted:
        return {}
    without_comments = "".join(clean)
    without_trailing = re.sub(r",(?=\s*[}\]])", "", without_comments)
    try:
        value = json.loads(without_trailing)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _read_config(path: Path, *, jsonc: bool = False) -> dict[str, Any]:
    try:
        if path.stat().st_size > _MAX_CONFIG_BYTES:
            return {}
        source = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    if jsonc:
        return _parse_jsonc(source)
    try:
        value = json.loads(source)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _merge_config(left: Mapping[str, Any], right: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(left) if isinstance(left, Mapping) else {}
    for key, value in right.items() if isinstance(right, Mapping) else ():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = _merge_config(merged[key], value)
        else:
            merged[key] = value
    return merged


def _opencode_config(cwd: Path, environ: Mapping[str, str]) -> dict[str, Any]:
    """Load only local OpenCode configuration needed to find credential refs."""
    home = Path(environ.get("HOME") or str(Path.home())).expanduser()
    config_home = Path(environ.get("XDG_CONFIG_HOME") or home / ".config").expanduser()
    paths = [
        config_home / "opencode/opencode.json",
        config_home / "opencode/opencode.jsonc",
    ]
    if environ.get("OPENCODE_CONFIG"):
        candidate = Path(environ["OPENCODE_CONFIG"]).expanduser()
        paths.append(candidate if candidate.is_absolute() else cwd / candidate)
    ancestors = list(reversed((cwd.resolve(), *cwd.resolve().parents)))
    for directory in ancestors:
        paths.extend((
            directory / "opencode.json", directory / "opencode.jsonc",
            directory / ".opencode/opencode.json",
            directory / ".opencode/opencode.jsonc",
        ))
    if environ.get("OPENCODE_CONFIG_DIR"):
        directory = Path(environ["OPENCODE_CONFIG_DIR"]).expanduser()
        paths.extend((directory / "opencode.json", directory / "opencode.jsonc"))
    merged: dict[str, Any] = {}
    seen: set[Path] = set()
    for path in paths:
        path = path.resolve()
        if path in seen:
            continue
        seen.add(path)
        merged = _merge_config(merged, _read_config(path, jsonc=path.suffix == ".jsonc"))
    if environ.get("OPENCODE_CONFIG_CONTENT"):
        merged = _merge_config(merged, _parse_jsonc(environ["OPENCODE_CONFIG_CONTENT"]))
    return merged


def _credential_env_names(
    config_path: Path,
    cwd: Path,
    environ: Mapping[str, str],
) -> set[str]:
    """Return credential variables explicitly selected by local model config."""
    names: set[str] = set()
    config = _read_config(config_path)
    providers = config.get("providers") if isinstance(config.get("providers"), Mapping) else {}
    for provider in providers.values():
        credential = provider.get("credential") if isinstance(provider, Mapping) else None
        if not isinstance(credential, Mapping):
            continue
        name = credential.get("env")
        if isinstance(name, str) and _ENV_NAME.fullmatch(name):
            names.add(name)
        if credential.get("openclaude") == "anthropic":
            names.add("ANTHROPIC_API_KEY")

    opencode = _opencode_config(cwd, environ)
    providers = opencode.get("provider") if isinstance(opencode.get("provider"), Mapping) else {}
    for provider in providers.values():
        if not isinstance(provider, Mapping):
            continue
        options = provider.get("options") if isinstance(provider.get("options"), Mapping) else {}
        match = _ENV_REFERENCE.fullmatch(str(options.get("apiKey") or ""))
        if match:
            names.add(match.group(1))
            continue
        candidates = provider.get("env") if isinstance(provider.get("env"), list) else []
        for name in candidates:
            if (isinstance(name, str) and _ENV_NAME.fullmatch(name)
                    and str(environ.get(name) or "").strip()):
                names.add(name)
                break
    return names


def _openclaude_child_environment(
    config_path: Path,
    cwd: Path,
    *,
    auth_file: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build a bounded environment for discovery and the provider sidecar."""
    source = os.environ if environ is None else environ
    allowed = (*_PROCESS_ENV, *_OPENCLAUDE_STATE_ENV)
    env = {name: source[name] for name in allowed if source.get(name)}
    env.setdefault("HOME", str(Path.home()))
    env.setdefault("PATH", os.defpath)
    env.setdefault("LANG", "C.UTF-8")
    for name in _credential_env_names(config_path, cwd, source):
        if source.get(name):
            env[name] = source[name]
    if auth_file is not None:
        env["OPENCLAUDE_AUTH_FILE"] = str(auth_file)
    env["NO_COLOR"] = "1"
    return env


def resolve_openclaude_route(route: str) -> str:
    """Translate legacy OpenCode provider IDs to OpenClaude's public routes."""
    value = str(route or "").strip()
    for old, new in _ROUTE_ALIASES.items():
        if value.startswith(old):
            return new + value[len(old):]
    return value


def _effort_levels(value: Mapping[str, Any]) -> tuple[str, ...]:
    effort = value.get("effort") if isinstance(value.get("effort"), Mapping) else {}
    levels = [str(item) for item in (effort.get("levels") or []) if isinstance(item, str)]
    for option in (value.get("reasoningOptions") or []):
        if not isinstance(option, Mapping):
            continue
        levels.extend(str(item) for item in (option.get("values") or []) if isinstance(item, str))
    aliases = effort.get("aliases") if isinstance(effort.get("aliases"), Mapping) else {}
    levels.extend(str(item) for item in aliases)
    levels.extend(str(item) for item in aliases.values() if isinstance(item, str))
    return tuple(dict.fromkeys(item for item in levels if item))


@dataclass(frozen=True)
class OpenClaudeModel:
    """Sanitized catalog metadata for one OpenClaude route."""

    route_id: str
    provider: str
    upstream_model: str
    label: str
    protocol: str
    status: str
    reason: str = ""
    tools: bool = False
    reasoning: bool = False
    temperature: bool = False
    input_modalities: tuple[str, ...] = ("text",)
    output_modalities: tuple[str, ...] = ("text",)
    context_window: int = 0
    max_output_tokens: int = 0
    efforts: tuple[str, ...] = ()
    effort_default: str = "auto"
    effort: str = "auto"
    aliases: tuple[str, ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_payload(cls, value: Mapping[str, Any]) -> "OpenClaudeModel":
        capabilities = value.get("capabilities") \
            if isinstance(value.get("capabilities"), Mapping) else {}
        limits = value.get("limits") if isinstance(value.get("limits"), Mapping) else {}
        effort = value.get("effort") if isinstance(value.get("effort"), Mapping) else {}
        inputs = capabilities.get("input") if isinstance(capabilities.get("input"), Mapping) else {}
        outputs = capabilities.get("output") if isinstance(capabilities.get("output"), Mapping) else {}
        return cls(
            route_id=_clean(value.get("routeId") or value.get("id"), 300),
            provider=_clean(value.get("provider"), 160),
            upstream_model=_clean(value.get("model"), 300),
            label=_clean(value.get("label") or value.get("routeId") or value.get("id"), 300),
            protocol=_clean(value.get("protocol"), 40),
            status=_clean(value.get("status"), 40),
            reason=_clean(value.get("reason"), 1000),
            tools=capabilities.get("tools") is True,
            reasoning=capabilities.get("reasoning") is True,
            temperature=capabilities.get("temperature") is True,
            input_modalities=tuple(key for key, enabled in inputs.items() if enabled is True),
            output_modalities=tuple(key for key, enabled in outputs.items() if enabled is True),
            context_window=int(limits.get("context") or 0),
            max_output_tokens=int(limits.get("output") or 0),
            efforts=_effort_levels(value),
            effort_default=_clean(effort.get("default") or "auto", 40),
            effort=_clean(effort.get("default") or "auto", 40),
            aliases=tuple(_clean(item, 300) for item in (value.get("aliases") or [])
                          if isinstance(item, str)),
            raw=dict(value),
        )

    def opencode_model(self, selected_effort: str = "") -> dict[str, Any]:
        """Return the custom-model entry consumed by OpenCode 1.18+."""
        variants = tuple(dict.fromkeys(("auto", *self.efforts, selected_effort)))
        model: dict[str, Any] = {
            "id": self.route_id,
            "name": self.label,
            "reasoning": self.reasoning,
            "temperature": self.temperature,
            "tool_call": self.tools,
            "limit": {
                "context": self.context_window or 200_000,
                "output": self.max_output_tokens or 32_768,
            },
            "modalities": {
                "input": list(self.input_modalities or ("text",)),
                "output": list(self.output_modalities or ("text",)),
            },
            # OpenCode validates --variant locally. OpenClaude applies the
            # selected effort at its gateway, so empty variants are deliberate.
            "variants": {name: {} for name in variants if name},
        }
        if self.status in {"alpha", "beta", "deprecated", "active"}:
            model["status"] = self.status
        return model


@lru_cache(maxsize=1)
def _discover_models() -> tuple[OpenClaudeModel, ...]:
    """Read one sanitized catalog snapshot for the current CLI process."""
    root = Path(
        os.environ.get("GRYPTON_OPENCLAUDE_HOME")
        or os.environ.get("GRYPTON_OPENCLAUDE_ROOT")
        or str(DEFAULT_OPENCLAUDE_ROOT)
    ).expanduser().resolve()
    config = Path(os.environ.get(
        "GRYPTON_OPENCLAUDE_CONFIG", str(root / "openclaude.config.json")
    )).expanduser().resolve()
    node_value = os.environ.get("GRYPTON_OPENCLAUDE_NODE") or "node"
    node = str(Path(node_value).expanduser().resolve()) if os.path.isabs(node_value) \
        else shutil.which(node_value)
    cli = root / "bin/openclaude.mjs"
    if not root.is_dir() or not cli.is_file() or not config.is_file():
        raise OpenClaudeError(f"OpenClaude installation is incomplete at {root}.")
    if not node or not Path(node).is_file() or not os.access(node, os.X_OK):
        raise OpenClaudeError("Node.js is required for OpenClaude model discovery.")

    try:
        result = subprocess.run(
            [node, str(cli), "--config", str(config), "models", "--all", "--json"],
            cwd=str(root),
            env=_openclaude_child_environment(config, root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OpenClaudeError("OpenClaude model discovery failed.") from exc
    if result.returncode != 0:
        raise OpenClaudeError("OpenClaude model discovery failed.")
    if len(result.stdout.encode("utf-8")) > _MAX_PROTOCOL_BYTES:
        raise OpenClaudeError("OpenClaude model catalog exceeded 32 MiB.")
    try:
        payload = json.loads(result.stdout)
    except (TypeError, ValueError) as exc:
        raise OpenClaudeError("OpenClaude returned an invalid model catalog.") from exc
    if not isinstance(payload, list):
        raise OpenClaudeError("OpenClaude returned an invalid model catalog.")

    return tuple(
        OpenClaudeModel.from_payload(value)
        for value in payload
        if isinstance(value, Mapping)
    )


def list_models(search: str = "") -> list[OpenClaudeModel]:
    """Return sanitized models from OpenClaude's local catalog.

    Discovery is synchronous so CLI argument validation can use it before an
    asyncio provider session exists. One process reuses its catalog snapshot,
    avoiding repeated 10+ MiB discovery output. A new CLI invocation gets a
    fresh snapshot. This does not start a gateway or make a provider request.
    """
    models = list(_discover_models())
    needle = str(search or "").strip().casefold()
    if not needle:
        return models
    return [
        model for model in models
        if any(needle in value.casefold() for value in (
            model.route_id,
            model.provider,
            model.upstream_model,
            model.label,
            *model.aliases,
        ))
    ]


def resolve_model(
    route: str,
    effort: str | None = None,
    require_tools: bool = False,
) -> OpenClaudeModel:
    """Resolve and validate one public OpenClaude route from the local catalog."""
    requested = resolve_openclaude_route(route)
    if not requested:
        raise OpenClaudeError("An OpenClaude model route is required.")
    models = list_models(requested)
    model = next((
        item for item in models
        if requested == item.route_id or requested in item.aliases
    ), None)
    if model is None:
        raise OpenClaudeError(f"Unknown OpenClaude route {requested!r}.")
    if model.status != "available":
        detail = f": {model.reason}" if model.reason else ""
        raise OpenClaudeError(
            f"OpenClaude route {model.route_id!r} is not available{detail}"
        )
    if require_tools and not model.tools:
        raise OpenClaudeError(
            f"OpenClaude route {model.route_id!r} does not support tool calls."
        )
    selected_effort = str(effort or "auto").strip() or "auto"
    if (selected_effort != "auto" and model.efforts
            and selected_effort not in model.efforts):
        supported = ", ".join(model.efforts)
        raise OpenClaudeError(
            f"Effort {selected_effort!r} is unsupported by {model.route_id}; "
            f"choose {supported}."
        )
    return replace(model, effort=selected_effort)

class OpenClaudeGateway:
    """Own one OpenClaude sidecar and its authenticated loopback gateway.

    Parameters match the role-specific lifecycle expected by Grypton's provider
    transport.  ``start`` performs local catalog discovery only; paid provider
    traffic begins only when a caller uses the returned gateway URL.
    """

    def __init__(
        self,
        route: str,
        effort: str,
        role: str,
        workspace: str | os.PathLike[str],
        event_callback: Optional[Callable[[dict], None]] = None,
        *,
        openclaude_root: str | os.PathLike[str] | None = None,
        config_path: str | os.PathLike[str] | None = None,
        node_binary: str | os.PathLike[str] | None = None,
        auth_file: str | os.PathLike[str] | None = None,
    ):
        root_value = (openclaude_root
                      or os.environ.get("GRYPTON_OPENCLAUDE_HOME")
                      or os.environ.get("GRYPTON_OPENCLAUDE_ROOT")
                      or str(DEFAULT_OPENCLAUDE_ROOT))
        self.openclaude_root = Path(root_value).expanduser().resolve()
        config_value = config_path or os.environ.get(
            "GRYPTON_OPENCLAUDE_CONFIG",
            str(self.openclaude_root / "openclaude.config.json"),
        )
        self.config_path = Path(config_value).expanduser().resolve()
        self.workspace = Path(workspace).expanduser().resolve()
        self.role = _clean(role, 80) or "provider"
        self.requested_route = str(route or "").strip()
        self.route = resolve_openclaude_route(self.requested_route)
        self.effort = str(effort or "auto").strip() or "auto"
        self.event_callback = event_callback
        self.auth_file = Path(auth_file).expanduser().resolve() if auth_file else None
        self.node_binary = self._resolve_node(node_binary)
        self._sidecar_path = Path(__file__).resolve().parent / "resources/openclaude_sidecar.mjs"
        self._token = secrets.token_hex(32)
        self._url = ""
        self._header_name = ""
        self._model: OpenClaudeModel | None = None
        self._catalog: tuple[OpenClaudeModel, ...] = ()
        self._proc: asyncio.subprocess.Process | None = None
        self._reader_task: asyncio.Task | None = None
        self._stderr_task: asyncio.Task | None = None
        self._pending: dict[int, asyncio.Future] = {}
        self._sequence = 0
        self._write_lock = asyncio.Lock()
        self._events: deque[dict] = deque(maxlen=1000)
        self._closed = False

    @staticmethod
    def _resolve_node(value: str | os.PathLike[str] | None) -> str:
        candidate = str(value or os.environ.get("GRYPTON_OPENCLAUDE_NODE") or "node")
        if os.path.isabs(candidate):
            path = Path(candidate)
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
            raise OpenClaudeError("Configured Node.js executable is unavailable.")
        found = shutil.which(candidate)
        if not found:
            raise OpenClaudeError("Node.js is required for the OpenClaude gateway.")
        return found

    def __repr__(self) -> str:
        state = "started" if self._url else "stopped"
        return (f"OpenClaudeGateway(route={self.route!r}, effort={self.effort!r}, "
                f"role={self.role!r}, state={state!r})")

    @property
    def url(self) -> str:
        if not self._url:
            raise OpenClaudeError("OpenClaude gateway has not been started.")
        return self._url

    @property
    def token(self) -> str:
        """Gateway bearer used only in a child-process environment; never log it."""
        if not self._url:
            raise OpenClaudeError("OpenClaude gateway has not been started.")
        return self._token

    @property
    def model(self) -> OpenClaudeModel:
        if self._model is None:
            raise OpenClaudeError("OpenClaude model metadata is unavailable before start().")
        return self._model

    @property
    def models(self) -> tuple[OpenClaudeModel, ...]:
        return self._catalog

    @property
    def model_route(self) -> str:
        """OpenCode-qualified route for the custom gateway provider."""
        return f"openclaude/{self.model.route_id}"

    def environment(self) -> dict[str, str]:
        """Return the minimal secret child environment for the provider binding."""
        if not self._url:
            raise OpenClaudeError("OpenClaude gateway has not been started.")
        return {TOKEN_ENV: self._token}

    def provider_config(self, provider_id: str = "openclaude") -> dict[str, Any]:
        """Build an OpenCode custom provider that preserves its JSON/MCP tools.

        OpenCode talks Anthropic Messages to the local gateway. OpenClaude then
        translates that request to the selected provider and owns key rotation.
        """
        provider = str(provider_id or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", provider):
            raise ValueError("provider_id must contain only letters, numbers, dots, underscores, or hyphens")
        return {
            provider: {
                "name": "OpenClaude gateway",
                "npm": "@ai-sdk/anthropic",
                "options": {
                    "baseURL": self.url.rstrip("/") + "/v1",
                    "apiKey": "{env:" + TOKEN_ENV + "}",
                    "timeout": False,
                },
                "models": {
                    self.model.route_id: self.model.opencode_model(self.effort),
                },
            }
        }

    async def start(self) -> "OpenClaudeGateway":
        if self._url:
            return self
        if self._closed:
            raise OpenClaudeError("A closed OpenClaude gateway cannot be restarted.")
        self._validate_installation()
        env = _openclaude_child_environment(
            self.config_path,
            self.workspace,
            auth_file=self.auth_file,
        )
        env[TOKEN_ENV] = self._token
        self.workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._proc = await asyncio.create_subprocess_exec(
            self.node_binary,
            str(self._sidecar_path),
            str(self.openclaude_root),
            str(self.config_path),
            cwd=str(self.workspace),
            env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            limit=_MAX_PROTOCOL_BYTES + 1,
        )
        self._reader_task = asyncio.create_task(self._read_stdout())
        self._stderr_task = asyncio.create_task(self._discard_stderr())
        try:
            ping = await self._request("ping", timeout=15)
            if int(ping.get("protocol") or 0) != _PROTOCOL_VERSION:
                raise OpenClaudeError("OpenClaude sidecar protocol mismatch.")
            catalog = await self._request("catalog", {"refresh": False}, timeout=30)
            values = catalog.get("models") if isinstance(catalog, Mapping) else []
            self._catalog = tuple(
                OpenClaudeModel.from_payload(value)
                for value in values or []
                if isinstance(value, Mapping)
            )
            self._model = self._select_model(self.route)
            if self._model.status != "available":
                detail = f": {self._model.reason}" if self._model.reason else ""
                raise OpenClaudeError(
                    f"OpenClaude route {self.route!r} is not available{detail}"
                )
            if (self.effort not in {"", "auto"} and self._model.efforts
                    and self.effort not in self._model.efforts):
                supported = ", ".join(self._model.efforts)
                raise OpenClaudeError(
                    f"Effort {self.effort!r} is unsupported by {self.route}; choose {supported}."
                )
            started = await self._request(
                "start", {"route": self.route, "effort": self.effort, "port": 0}, timeout=30
            )
            self._url = _clean(started.get("url"), 500)
            self._header_name = _clean(started.get("headerName"), 160)
            if not re.fullmatch(r"http://127\.0\.0\.1:\d+", self._url):
                raise OpenClaudeError("OpenClaude gateway did not bind to loopback.")
            self._emit({
                "type": "openclaude_gateway",
                "status": "started",
                "role": self.role,
                "route": self.route,
                "effort": self.effort,
                "model": self._model.label,
            })
            return self
        except BaseException:
            await self.close()
            raise

    def _validate_installation(self) -> None:
        required = (
            self.openclaude_root / "src/config.mjs",
            self.openclaude_root / "src/catalog.mjs",
            self.openclaude_root / "src/gateway.mjs",
            self.openclaude_root / "package.json",
            self.config_path,
            self._sidecar_path,
        )
        if not self.openclaude_root.is_dir() or any(not path.is_file() for path in required):
            raise OpenClaudeError(
                f"OpenClaude installation is incomplete at {self.openclaude_root}."
            )

    def _select_model(self, route: str) -> OpenClaudeModel:
        for model in self._catalog:
            if route == model.route_id or route in model.aliases:
                self.route = model.route_id
                return model
        raise OpenClaudeError(
            f"Unknown OpenClaude route {route!r}; inspect the local catalog before starting."
        )

    async def _request(
        self,
        method: str,
        params: Optional[Mapping[str, Any]] = None,
        *,
        timeout: float = 20,
    ) -> Mapping[str, Any]:
        if self._proc is None or self._proc.returncode is not None or self._proc.stdin is None:
            raise OpenClaudeError("OpenClaude sidecar is not running.")
        loop = asyncio.get_running_loop()
        self._sequence += 1
        request_id = self._sequence
        future = loop.create_future()
        self._pending[request_id] = future
        payload = json.dumps({"id": request_id, "method": method, "params": dict(params or {})})
        try:
            async with self._write_lock:
                self._proc.stdin.write((payload + "\n").encode("utf-8"))
                await self._proc.stdin.drain()
            result = await asyncio.wait_for(future, timeout=timeout)
        except BaseException:
            self._pending.pop(request_id, None)
            raise
        if not isinstance(result, Mapping):
            raise OpenClaudeError("OpenClaude sidecar returned an invalid result.")
        return result

    async def _read_stdout(self) -> None:
        assert self._proc and self._proc.stdout
        try:
            while line := await self._proc.stdout.readline():
                if len(line) > _MAX_PROTOCOL_BYTES:
                    raise OpenClaudeError("OpenClaude sidecar message exceeded 4 MB.")
                try:
                    value = json.loads(line)
                except (UnicodeDecodeError, ValueError):
                    continue
                if not isinstance(value, dict):
                    continue
                event = value.get("event")
                if isinstance(event, dict):
                    self._emit(self._sanitize_event(event))
                    continue
                request_id = value.get("id")
                future = self._pending.pop(request_id, None)
                if future is None or future.done():
                    continue
                if value.get("ok") is True:
                    future.set_result(value.get("result") or {})
                else:
                    future.set_exception(OpenClaudeError(
                        _clean(value.get("error") or "OpenClaude sidecar request failed", 1000)
                    ))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._fail_pending(OpenClaudeError(_clean(exc, 1000)))
        finally:
            if self._proc and self._proc.returncode is None:
                await self._proc.wait()
            self._fail_pending(OpenClaudeError("OpenClaude sidecar stopped unexpectedly."))

    async def _discard_stderr(self) -> None:
        """Drain diagnostics without retaining text that might name local secrets."""
        assert self._proc and self._proc.stderr
        try:
            while await self._proc.stderr.read(65_536):
                pass
        except asyncio.CancelledError:
            raise

    @staticmethod
    def _sanitize_event(event: Mapping[str, Any]) -> dict:
        kind = _clean(event.get("type"), 80)
        if kind == "openclaude_notice":
            raw_message = re.sub(
                r"\b(key\s+)[a-f0-9]{8}\b", r"\1[REDACTED]",
                str(event.get("message") or ""), flags=re.IGNORECASE,
            )
            message = re.sub(
                r"\b(key\s+)[a-f0-9]{8}\b", r"\1[REDACTED]",
                _clean(raw_message, 1500), flags=re.IGNORECASE,
            )
            return {"type": kind, "route": _clean(event.get("route"), 300),
                    "message": message}
        if kind == "openclaude_terminal":
            try:
                status = int(event.get("upstreamStatus") or 0)
            except (TypeError, ValueError):
                status = 0
            try:
                pool_size = int(event.get("poolSize") or 0)
            except (TypeError, ValueError):
                pool_size = 0
            return {
                "type": kind,
                "route": _clean(event.get("route"), 300),
                "reason": (
                    "credential_pool_exhausted"
                    if event.get("reason") == "credential_pool_exhausted"
                    else "provider_terminal"
                ),
                "upstream_status": status if 100 <= status <= 599 else 0,
                "pool_size": pool_size if 0 < pool_size <= 1000 else 0,
            }
        if kind == "openclaude_request":
            return {
                "type": kind,
                "route": _clean(event.get("route"), 300),
                "protocol": _clean(event.get("protocol"), 40),
                "tools": [_clean(item, 160) for item in event.get("tools", [])[:100]],
                "messages": int(event.get("messages") or 0),
                "stream": event.get("stream") is True,
            }
        if kind == "openclaude_effort":
            return {
                "type": kind,
                "route": _clean(event.get("route"), 300),
                "requested": _clean(event.get("requested"), 40),
                "effective": _clean(event.get("effective"), 40),
                "status": _clean(event.get("status"), 80),
                "notices": [_clean(item, 500) for item in event.get("notices", [])[:20]],
            }
        return {"type": "openclaude_event", "event": kind or "unknown"}

    def _emit(self, event: dict) -> None:
        self._events.append(event)
        if self.event_callback is not None:
            try:
                self.event_callback(event)
            except Exception:
                pass

    def drain_events(self) -> list[dict]:
        events = list(self._events)
        self._events.clear()
        return events

    def _fail_pending(self, error: Exception) -> None:
        for future in tuple(self._pending.values()):
            if not future.done():
                future.set_exception(error)
        self._pending.clear()

    async def status(self) -> Mapping[str, Any]:
        return await self._request("status", timeout=10)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        proc = self._proc
        if proc is not None and proc.returncode is None:
            try:
                await self._request("shutdown", timeout=5)
            except Exception:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                await proc.wait()
        current = asyncio.current_task()
        for task in (self._reader_task, self._stderr_task):
            if task is not None and task is not current and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (self._reader_task, self._stderr_task)
              if task is not None and task is not current),
            return_exceptions=True,
        )
        self._proc = None
        self._reader_task = None
        self._stderr_task = None
        self._url = ""
        self._fail_pending(OpenClaudeError("OpenClaude gateway closed."))

    async def __aenter__(self) -> "OpenClaudeGateway":
        return await self.start()

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        await self.close()


__all__ = [
    "DEFAULT_OPENCLAUDE_ROOT",
    "OpenClaudeError",
    "OpenClaudeGateway",
    "OpenClaudeModel",
    "TOKEN_ENV",
    "list_models",
    "resolve_model",
    "resolve_openclaude_route",
]
