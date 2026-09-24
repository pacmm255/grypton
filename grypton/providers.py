"""Provider transports for persistent OpenCode roles and independent Codex validation."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import Callable, Optional

from . import config
from .openclaude import OpenClaudeError, OpenClaudeGateway


MAX_STREAM_BYTES = 16_000_000
MCP_TIMEOUT_MS = 120_000
MAX_ASSISTANT_TEXT_CHARS = 12_000
_OPENCODE_VERSION: Optional[str] = None
_CONTROL = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|"
    r"[\x00-\x08\x0b-\x1f\x7f-\x9f]"
)

_STATUS_GLYPH = r"(?:\u2705|\u2611\ufe0f?|\u2714\ufe0f?|\U0001f3c1|\U0001f680|\U0001faf0|\U0001f3ac|\U0001f389|\U0001f44d|\u2728)"
_STATUS_GLYPH_RUN = re.compile(rf"(?:{_STATUS_GLYPH}[\s,.;:!\-]*){{2,}}")
_ONLY_STATUS_GLYPHS = re.compile(rf"^(?:{_STATUS_GLYPH}|[\s,.;:!\-_*#])+$")
_META_CHATTER = re.compile(
    r"(?:"
    r"\b(?:now|time\s+to|let\s+me|i\s+(?:will|should|must|can|'ll))\b"
    r".{0,60}\b(?:provide|emit|write|deliver|send|give)\b"
    r".{0,40}\b(?:final|answer|response)\b"
    r"|\b(?:final\s+(?:answer|response))\s+(?:follows|below|now|next)\b"
    r"|\bno\s+more\s+(?:delays?|thinking|analysis)\b"
    r"|\b(?:end|stop)\s+(?:of\s+)?(?:thinking|analysis)\b"
    r"|\b(?:just|simply)\s+(?:answer|emit|respond)\b"
    r")",
    re.IGNORECASE,
)
_VACUOUS_LINE = re.compile(
    r"^(?:ok(?:ay)?|sure|understood|done|finished|ready|goodbye|"
    r"let(?:'s| us)\s+(?:go|proceed|finish)|final(?:\s+(?:answer|response))?|"
    r"answer\s+follows)[\s.!:;-]*$",
    re.IGNORECASE,
)
_SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9])")
_TEXT_TRUNCATION_MARKER = "\n\n[... normalized response truncated ...]\n\n"


class ProviderError(RuntimeError):
    """Provider failure with optional sanitized machine-readable context."""

    def __init__(self, message: str, *, metadata: Optional[dict] = None):
        super().__init__(message)
        self.metadata = dict(metadata or {})


def tool_state_text(state: dict) -> str:
    """Return the payload OpenCode uses for either a tool result or failure."""
    for key in ("output", "error", "message"):
        value = state.get(key)
        if value not in (None, ""):
            if isinstance(value, str):
                return value
            try:
                return json.dumps(value, ensure_ascii=False)
            except (TypeError, ValueError):
                return str(value)
    return ""


def private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path


def atomic_json(path: Path, value) -> None:
    private_dir(path.parent)
    temporary = path.with_name("." + path.name + ".tmp")
    fd = os.open(temporary, os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def append_jsonl(path: Path, value) -> None:
    private_dir(path.parent)
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, ensure_ascii=False) + "\n")
        stream.flush()


def clean(text: str, secrets=()) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"(?i)(bearer\s+)[\w.\-]+", r"\1[REDACTED]", text)
    text = re.sub(r"\bsk-[A-Za-z0-9_-]{12,}", "[REDACTED]", text)
    return _CONTROL.sub("", text)


def _bounded_assistant_text(text: str) -> tuple[str, bool]:
    """Bound model prose while retaining useful context at both ends."""
    if len(text) <= MAX_ASSISTANT_TEXT_CHARS:
        return text, False
    available = MAX_ASSISTANT_TEXT_CHARS - len(_TEXT_TRUNCATION_MARKER)
    head_size = available // 2
    tail_size = available - head_size
    bounded = (
        text[:head_size].rstrip()
        + _TEXT_TRUNCATION_MARKER
        + text[-tail_size:].lstrip()
    )
    return bounded[:MAX_ASSISTANT_TEXT_CHARS], True


def _assistant_text_segments(text: str) -> list[str]:
    """Split prose enough to isolate runaway meta chatter without rewriting it."""
    segments: list[str] = []
    for raw_line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw_line.rstrip()
        if not line.strip():
            segments.append("")
            continue
        # Degenerate responses sometimes put hundreds of short status
        # sentences on one physical line. Ordinary prose and code retain their
        # original line boundaries.
        if len(line) > 500 and _META_CHATTER.search(line):
            segments.extend(piece.strip() for piece in _SENTENCE_BREAK.split(line))
        else:
            segments.append(line)
    return segments


def _normalize_assistant_text(text: str) -> str:
    """Remove transport-level output degeneration while preserving evidence prose."""
    kept: list[str] = []
    seen: set[str] = set()
    pending_blank = False
    for segment in _assistant_text_segments(text):
        if not segment:
            pending_blank = bool(kept)
            continue
        original = segment
        segment = _STATUS_GLYPH_RUN.sub("", segment).rstrip()
        stripped = segment.strip()
        if not stripped or _ONLY_STATUS_GLYPHS.fullmatch(stripped):
            continue
        classification = re.sub(
            rf"^(?:{_STATUS_GLYPH}\s*)+", "", stripped
        ).strip()
        if (_VACUOUS_LINE.fullmatch(classification)
                or _META_CHATTER.search(classification)):
            continue

        # Ignore Markdown decoration and whitespace when detecting repeated
        # prose, but retain the first occurrence exactly as written.
        identity = re.sub(r"\s+", " ", classification).strip().casefold()
        identity = re.sub(rf"^(?:[-*#>\s]|{_STATUS_GLYPH})+", "", identity)
        if not identity or identity in seen:
            continue
        seen.add(identity)
        if pending_blank and kept and kept[-1] != "":
            kept.append("")
        pending_blank = False
        kept.append(original if segment == original else segment.strip())

    normalized = "\n".join(kept).strip()
    return _bounded_assistant_text(normalized)[0] if normalized else ""


def _select_assistant_text(parts: list[str]) -> tuple[str, dict]:
    """Select the last substantive OpenCode text part and describe filtering.

    The caller keeps the streamed events verbatim in the event transcript.
    This helper only derives the bounded text returned to the orchestrator.
    """
    raw_parts = [part for part in parts if isinstance(part, str) and part.strip()]
    if not raw_parts:
        return "", {
            "raw_text_part_count": 0,
            "raw_text_chars": 0,
            "raw_final_text_chars": 0,
            "normalized_text_chars": 0,
            "selected_text_part_index": None,
            "text_filtered": False,
            "text_truncated": False,
        }

    raw_final_source = raw_parts[-1]
    raw_final = raw_final_source.strip()
    selected = ""
    selected_index: int | None = None
    for index in range(len(raw_parts) - 1, -1, -1):
        candidate = _normalize_assistant_text(raw_parts[index])
        if candidate:
            selected = candidate
            selected_index = index
            break

    if not selected:
        selected = "[OpenCode completed without a substantive final response.]"
    truncated = _TEXT_TRUNCATION_MARKER.strip() in selected
    metadata = {
        "raw_text_part_count": len(raw_parts),
        "raw_text_chars": sum(len(part) for part in raw_parts),
        "raw_final_text_chars": len(raw_final_source),
        "normalized_text_chars": len(selected),
        "selected_text_part_index": selected_index,
        "text_filtered": selected_index != len(raw_parts) - 1 or selected != raw_final,
        "text_truncated": truncated,
    }
    return selected, metadata


def _minimal_child_environment() -> dict[str, str]:
    """Return the non-secret process context needed by OpenCode and MCP tools.

    OpenCode can launch model-selected tools, so copying the operator's complete
    environment into it would expose unrelated cloud, source-control, and
    service credentials. Provider authentication belongs to the separate
    OpenClaude sidecar; the only secret OpenCode receives is that sidecar's
    short-lived loopback token, added later by the provider environment.
    """
    allowed = (
        "HOME", "USER", "LOGNAME", "SHELL", "PATH", "TMPDIR", "LANG",
        "LC_ALL", "LC_CTYPE", "TZ", "TERM", "COLORTERM", "SSL_CERT_FILE",
        "SSL_CERT_DIR", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE",
    )
    env = {key: os.environ[key] for key in allowed if os.environ.get(key)}
    env.setdefault("HOME", str(Path.home()))
    env.setdefault("PATH", os.defpath)
    env.setdefault("LANG", "C.UTF-8")
    # The model provider is a loopback gateway. Never allow an inherited proxy
    # setting to divert that authenticated local connection elsewhere.
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["no_proxy"] = env["NO_PROXY"]
    return env


def _codex_child_environment() -> dict[str, str]:
    """Return only the process state needed for direct Codex authentication.

    The validator has every interactive/tool feature disabled, but inheriting
    unrelated deployment, source-control, and cloud credentials still expands
    the blast radius of a provider or subprocess defect. Codex can authenticate
    from `$CODEX_HOME`/`$HOME/.codex` or the explicitly supported OpenAI
    environment variables below. Endpoint-routing variables are deliberately
    omitted so the fixed Astra route cannot be redirected by ambient process
    configuration.
    """
    env = _minimal_child_environment()
    for key in (
        "CODEX_HOME", "OPENAI_API_KEY",
        "OPENAI_ORGANIZATION", "OPENAI_ORG_ID",
        "OPENAI_PROJECT", "OPENAI_PROJECT_ID",
    ):
        if os.environ.get(key):
            env[key] = os.environ[key]
    return env


def _host_xdg(kind: str, default: str) -> Path:
    return Path(os.environ.get(f"XDG_{kind}_HOME", str(Path.home() / default)))


def _installed_opencode_version() -> str:
    """Return the CLI version used to select a matching local plugin SDK."""
    global _OPENCODE_VERSION
    if _OPENCODE_VERSION is not None:
        return _OPENCODE_VERSION
    try:
        result = subprocess.run(
            [config.require_binary("opencode"), "--version"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
        )
        _OPENCODE_VERSION = result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        _OPENCODE_VERSION = ""
    return _OPENCODE_VERSION


def _package_version(directory: Path) -> str:
    try:
        value = json.loads((directory / "package.json").read_text(encoding="utf-8"))
        return str(value.get("version") or value.get("dependencies", {}).get(
            "@opencode-ai/plugin", ""
        ))
    except (OSError, ValueError, AttributeError):
        return ""


def _seed_opencode_dependencies(destination: Path) -> None:
    """Hardlink a matching local SDK so isolated roles never race npm setup."""
    version = _installed_opencode_version()
    plugin = destination / "node_modules/@opencode-ai/plugin"
    if not version or _package_version(plugin) == version:
        return
    candidates = [_host_xdg("CONFIG", ".config") / "opencode"]
    for role in ("worker", "manager"):
        candidates.extend(config.PROVIDER_DIR.glob(f"*/{role}/config/opencode"))
    source = next((candidate for candidate in candidates
                   if candidate != destination
                   and _package_version(candidate) == version
                   and _package_version(candidate / "node_modules/@opencode-ai/plugin") == version
                   and (candidate / "package-lock.json").is_file()), None)
    if source is None:
        return
    private_dir(destination)
    modules = destination / "node_modules"
    if modules.exists():
        modules.replace(destination / f"node_modules.incomplete-{time.time_ns()}")

    def link_or_copy(source_path: str, target_path: str) -> str:
        try:
            os.link(source_path, target_path)
            return target_path
        except OSError:
            return shutil.copy2(source_path, target_path)

    shutil.copytree(source / "node_modules", modules, copy_function=link_or_copy)
    for name in ("package.json", "package-lock.json"):
        shutil.copy2(source / name, destination / name)




async def _terminate(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except asyncio.TimeoutError:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await proc.wait()


@dataclass
class OpenCodeResult:
    text: str
    session_id: str
    events: list[dict]
    tools: list[dict]
    usage: list[dict]
    duration_s: float
    cost: float = 0.0
    stderr: str = ""
    returncode: int = 0


class OpenCodeClient:
    """One role-specific OpenCode session with isolated, persistent XDG state."""

    @staticmethod
    def _permissions(allow_tools: bool, workspace: Path | None = None,
                     transport_workspace: Path | None = None) -> dict:
        if not allow_tools:
            return {
                "*": "deny",
                "question": "deny",
                "task": "deny",
                "external_directory": "deny",
            }

        # A command-name blacklist cannot contain a native shell: Python,
        # Node, /dev/tcp, copied binaries, and package hooks can all perform
        # unscoped I/O or read private credentials. Local documents remain
        # available through OpenCode's bounded file tools; every network and
        # protocol action must cross the observable grypton_* MCP boundary.
        bash = "deny"

        # OpenCode runs inside a small transport directory rather than the
        # Grypton checkout.  The engagement itself is deliberately outside
        # that directory, so a blanket external-directory denial makes even
        # its own scope file unreadable.  Give the worker access only to the
        # one engagement and its transport directory; every other external
        # path remains denied.  Manager sessions have no filesystem tools.
        external_directory: str | dict = "deny"
        allowed_external = [path.resolve() for path in (workspace, transport_workspace)
                            if path is not None]
        if allowed_external:
            # OpenCode permission patterns are evaluated in insertion order
            # with the last matching rule winning. Put the catch-all first so
            # the two narrow workspace grants can override it.
            external_directory = {
                "*": "deny",
                **{str(path / "*"): "allow" for path in allowed_external},
            }

        return {
            "*": "allow",
            "bash": bash,
            "edit": "deny",
            "webfetch": "deny",
            "websearch": "deny",
            "question": "deny",
            "task": "deny",
            "external_directory": external_directory,
        }

    def __init__(
        self,
        *,
        role: str,
        route: str,
        effort: str,
        workspace: Path,
        target_slug: str,
        allow_tools: bool,
        agent_prompt: str,
        event_callback: Optional[Callable[[dict], None]] = None,
    ):
        self.role = role
        self.route = route
        self.provider = route.split("/", 1)[0]
        self.effort = effort
        self.workspace = workspace.resolve()
        self.target_slug = target_slug
        self.allow_tools = allow_tools
        self.agent_prompt = agent_prompt
        self.event_callback = event_callback
        self.runtime = private_dir(config.PROVIDER_DIR / target_slug / role)
        # OpenCode discovers the parent Git checkout itself and performs project
        # copy/snapshot work before the first model event. Engagements live under
        # the Grypton checkout, so use a tiny persistent transport directory
        # outside that repository. Evidence and transcripts remain in the real
        # engagement workspace, and the MCP server resolves it from target_slug.
        transport_root = private_dir(config.OPENCODE_WORKSPACES_DIR)
        self.transport_workspace = private_dir(transport_root / target_slug / role)
        engagement_link = self.transport_workspace / "engagement"
        if engagement_link.is_symlink() and engagement_link.resolve() != self.workspace:
            engagement_link.unlink()
        if not engagement_link.exists():
            engagement_link.symlink_to(self.workspace, target_is_directory=True)
        self.transcripts = private_dir(self.workspace / "transcripts")
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.gateway: OpenClaudeGateway | None = None
        self._terminal_signal: asyncio.Event | None = None
        self._terminal_error = ""
        self._terminal_metadata: dict = {}

    def _on_gateway_event(self, event: dict) -> None:
        """Retain sanitized OpenClaude notices and expose them to the live UI."""
        append_jsonl(self.transcripts / "openclaude.events.jsonl", {
            "at": time.time(), "role": self.role, **event,
        })
        if event.get("type") == "openclaude_terminal":
            try:
                status = int(event.get("upstream_status") or 0)
            except (TypeError, ValueError):
                status = 0
            suffix = f" (upstream HTTP {status})" if status else ""
            self._terminal_error = (
                f"{self.role} OpenClaude credential pool exhausted{suffix}."
            )
            self._terminal_metadata = {
                "source": "openclaude",
                "type": "openclaude_terminal",
                "role": self.role,
                "reason": (
                    "credential_pool_exhausted"
                    if event.get("reason") == "credential_pool_exhausted"
                    else "provider_terminal"
                ),
                "upstream_status": status if 100 <= status <= 599 else 0,
                "pool_size": (
                    event.get("pool_size")
                    if isinstance(event.get("pool_size"), int)
                    and 0 < event["pool_size"] <= 1000 else 0
                ),
            }
            if self._terminal_signal is not None:
                self._terminal_signal.set()
        if self.event_callback:
            try:
                self.event_callback(event)
            except Exception:
                pass

    async def _ensure_gateway(self) -> OpenClaudeGateway:
        # Preserve one sidecar across calls so its spent-key cooldown survives.
        # If that process died between calls, rebuild it before a new request;
        # never replay a call that may already have streamed or used tools.
        if self.gateway is not None:
            try:
                await self.gateway.status()
            except Exception:
                try:
                    await self.gateway.close()
                except Exception:
                    pass
                self.gateway = None
        if self.gateway is None:
            self.gateway = OpenClaudeGateway(
                self.route,
                self.effort,
                self.role,
                self.transport_workspace,
                self._on_gateway_event,
            )
        try:
            await self.gateway.start()
        except OpenClaudeError as exc:
            try:
                await self.gateway.close()
            except Exception:
                pass
            self.gateway = None
            raise ProviderError(f"{self.role} OpenClaude gateway failed: {exc}") from exc
        # OpenClaude owns the canonical public ID (for example go/... rather
        # than OpenCode's credential-store ID opencode-go/...).
        self.route = self.gateway.model.route_id
        self.provider = self.gateway.model.provider
        return self.gateway

    def _environment(self) -> tuple[dict, str]:
        if self.gateway is None:
            raise ProviderError("OpenClaude gateway must be started before building OpenCode state.")
        gateway = self.gateway
        for kind in ("config", "data", "cache", "state"):
            private_dir(self.runtime / kind)
        _seed_opencode_dependencies(self.runtime / "config/opencode")

        permissions = self._permissions(
            self.allow_tools,
            self.workspace if self.allow_tools else None,
            self.transport_workspace if self.allow_tools else None,
        )
        transport_provider = "openclaude"
        transport_route = gateway.model_route
        inline = {
            "$schema": "https://opencode.ai/config.json",
            "snapshot": False,
            "enabled_providers": [transport_provider],
            "provider": gateway.provider_config(transport_provider),
            "model": transport_route,
            "small_model": transport_route,
            "default_agent": f"grypton-{self.role}",
            "permission": permissions,
            "share": "disabled",
            "autoupdate": False,
            "plugin": [],
            "agent": {
                f"grypton-{self.role}": {
                    "description": f"Grypton {self.role}",
                    "mode": "primary",
                    "model": transport_route,
                    "prompt": self.agent_prompt,
                    "permission": permissions,
                    "steps": 40 if self.allow_tools else 4,
                }
            },
            "mcp": {},
        }
        if self.allow_tools:
            inline["mcp"] = {
                "grypton": {
                    "type": "local",
                    "command": [sys.executable, "-m", "grypton.toolserver"],
                    "cwd": str(config.GRYPTON_HOME),
                    "enabled": True,
                    "timeout": MCP_TIMEOUT_MS,
                    "environment": {
                        "GRYPTON_HOME": str(config.GRYPTON_HOME),
                        "GRYPTON_TARGET": self.target_slug,
                        "KRYPTON_HOME": str(config.GRYPTON_HOME),
                        "KRYPTON_TARGET": self.target_slug,
                        "PYTHONPATH": str(config.SOURCE_ROOT),
                    },
                }
            }

        env = _minimal_child_environment()
        env.update({
            "XDG_CONFIG_HOME": str(self.runtime / "config"),
            "XDG_DATA_HOME": str(self.runtime / "data"),
            "XDG_CACHE_HOME": str(self.runtime / "cache"),
            "XDG_STATE_HOME": str(self.runtime / "state"),
            "OPENCODE_CONFIG_CONTENT": json.dumps(inline),
            "OPENCODE_CONFIG_DIR": str(self.runtime / "config/opencode"),
            "OPENCODE_DISABLE_CLAUDE_CODE": "true",
            "OPENCODE_DISABLE_PROJECT_CONFIG": "true",
            "OPENCODE_DISABLE_CLAUDE_CODE_SKILLS": "true",
            "OPENCODE_DISABLE_DEFAULT_PLUGINS": "true",
            "OPENCODE_EXPERIMENTAL_DISABLE_COPY_ON_SELECT": "true",
            "OPENCODE_PERMISSION": json.dumps(permissions),
            "GIT_CEILING_DIRECTORIES": str(config.GRYPTON_HOME),
            "GRYPTON_HOME": str(config.GRYPTON_HOME),
            "GRYPTON_TARGET": self.target_slug,
            "GRYPTON_ENGAGEMENT_DIR": str(self.workspace),
            "KRYPTON_HOME": str(config.GRYPTON_HOME),
            "KRYPTON_TARGET": self.target_slug,
            "PATH": f"{config.BIN_DIR}:{env.get('PATH', '')}",
            "NO_COLOR": "1",
            **gateway.environment(),
        })
        source_path = str(config.SOURCE_ROOT)
        inherited_pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = source_path + (
            os.pathsep + inherited_pythonpath if inherited_pythonpath else ""
        )
        return env, gateway.token

    async def call(
        self,
        prompt: str,
        *,
        session_id: str = "",
        timeout: float = 1800,
        title: str = "",
    ) -> OpenCodeResult:
        binary = config.require_binary("opencode")
        gateway = await self._ensure_gateway()
        env, secret = self._environment()
        transport_route = gateway.model_route
        argv = [
            binary, "run", "--pure", "--format", "json",
            "--model", transport_route, "--variant", self.effort,
            "--agent", f"grypton-{self.role}",
            "--title", title or f"Grypton {self.role}",
            "--dir", str(self.transport_workspace), "--thinking",
        ]
        if self.allow_tools:
            argv.append("--auto")
        if session_id:
            argv += ["--session", session_id]

        started = time.time()
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        self.proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(self.transport_workspace),
            env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        self._terminal_signal = asyncio.Event()
        self._terminal_error = ""
        self._terminal_metadata = {}
        assert self.proc.stdin and self.proc.stdout and self.proc.stderr
        self.proc.stdin.write(prompt.encode("utf-8"))
        await self.proc.stdin.drain()
        self.proc.stdin.close()

        events: list[dict] = []
        malformed: list[str] = []
        cleaned_lines: list[str] = []
        stream_path = self.transcripts / f"{self.role}.opencode.events.jsonl"

        def consume_stdout_line(raw: bytes) -> None:
            line = clean(raw.decode("utf-8", errors="replace"), (secret,))
            if not line.strip():
                return
            cleaned_lines.append(line)
            try:
                event = json.loads(line)
            except ValueError:
                malformed.append(line[:500])
                return
            if not isinstance(event, dict):
                malformed.append(line[:500])
                return
            events.append(event)
            append_jsonl(stream_path, event)
            if self.event_callback:
                try:
                    self.event_callback(event)
                except Exception:
                    pass

        async def read_stdout(stream) -> str:
            """Parse newline JSON as OpenCode emits it so tools render live."""
            pending = b""
            total = 0
            while block := await stream.read(65536):
                total += len(block)
                if total > MAX_STREAM_BYTES:
                    raise ProviderError("OpenCode event stream exceeded 16 MB.")
                pending += block
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    consume_stdout_line(line)
            if pending:
                consume_stdout_line(pending)
            return "\n".join(cleaned_lines)

        async def read_limited(stream) -> bytes:
            chunks: list[bytes] = []
            total = 0
            while block := await stream.read(65536):
                total += len(block)
                if total > MAX_STREAM_BYTES:
                    raise ProviderError("OpenCode event stream exceeded 16 MB.")
                chunks.append(block)
            return b"".join(chunks)

        stdout_task = asyncio.create_task(read_stdout(self.proc.stdout))
        stderr_task = asyncio.create_task(read_limited(self.proc.stderr))
        io_task = asyncio.gather(stdout_task, stderr_task, self.proc.wait())
        terminal_task = asyncio.create_task(self._terminal_signal.wait())
        failure_class = ""

        def append_failure_record(exc: BaseException, classification: str) -> None:
            """Record one sanitized row for a call that cannot reach final parsing."""
            partial_stdout = "\n".join(cleaned_lines)
            stderr_bytes = b""
            if stderr_task.done() and not stderr_task.cancelled():
                try:
                    value = stderr_task.result()
                except BaseException:
                    value = b""
                if isinstance(value, bytes):
                    stderr_bytes = value
            cleaned_stderr = clean(
                stderr_bytes.decode("utf-8", errors="replace"), (secret,)
            )
            if cleaned_stderr:
                append_jsonl(stream_path, {
                    "type": "stderr", "text": cleaned_stderr[-8000:],
                })
            if malformed:
                append_jsonl(stream_path, {
                    "type": "malformed", "lines": malformed,
                })

            result_session = session_id
            for event in events:
                candidate = event.get("sessionID") or event.get("session_id")
                if isinstance(candidate, str) and candidate:
                    result_session = candidate

            metadata = exc.metadata if isinstance(exc, ProviderError) else {}
            source = metadata.get("source")
            reason = metadata.get("reason")
            try:
                upstream_status = int(metadata.get("upstream_status") or 0)
            except (TypeError, ValueError):
                upstream_status = 0
            try:
                pool_size = int(metadata.get("pool_size") or 0)
            except (TypeError, ValueError):
                pool_size = 0

            record = {
                "at": time.time(),
                "role": self.role,
                "route": self.route,
                "effort": self.effort,
                "transport_route": transport_route,
                "runner": "opencode",
                "gateway": "openclaude",
                "session_id": result_session,
                "resumed": bool(session_id),
                "duration_s": round(time.time() - started, 3),
                "returncode": self.proc.returncode,
                "event_count": len(events),
                "tool_count": sum(
                    event.get("type") == "tool_use" for event in events
                ),
                "usage": [],
                "cost": 0.0,
                "prompt_sha256": prompt_hash,
                "stdout_sha256": hashlib.sha256(
                    partial_stdout.encode("utf-8")
                ).hexdigest(),
                "stderr_present": bool(cleaned_stderr),
                "ok": False,
                "error_class": classification,
                "error_type": type(exc).__name__,
                "error_message": clean(str(exc), (secret,))[:1000],
            }
            if isinstance(source, str) and source:
                record["error_source"] = clean(source, (secret,))[:100]
            if isinstance(reason, str) and reason:
                record["error_reason"] = clean(reason, (secret,))[:100]
            if 100 <= upstream_status <= 599:
                record["upstream_status"] = upstream_status
            if 0 < pool_size <= 1000:
                record["pool_size"] = pool_size
            try:
                gateway_events = gateway.drain_events()
            except Exception:
                gateway_events = []
            record["failover_count"] = sum(
                1 for event in gateway_events
                if event.get("type") == "openclaude_notice"
                and "continuing on key" in str(event.get("message") or "")
            )
            append_jsonl(self.transcripts / "provider-calls.jsonl", record)

        try:
            done, _ = await asyncio.wait(
                (io_task, terminal_task), timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                failure_class = "timeout"
                await _terminate(self.proc)
                await asyncio.gather(io_task, return_exceptions=True)
                raise ProviderError(
                    f"{self.role} OpenCode call timed out after {timeout:g}s."
                )
            if terminal_task in done and terminal_task.result():
                failure_class = "openclaude_terminal"
                await _terminate(self.proc)
                await asyncio.gather(io_task, return_exceptions=True)
                raise ProviderError(
                    self._terminal_error
                    or f"{self.role} OpenClaude provider became terminal.",
                    metadata=self._terminal_metadata,
                )
            cleaned_stdout, stderr, returncode = await io_task
        except ProviderError as exc:
            if not failure_class:
                failure_class = "stream_error"
            if self.proc.returncode is None:
                await _terminate(self.proc)
            await asyncio.gather(io_task, return_exceptions=True)
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            append_failure_record(exc, failure_class)
            raise
        except BaseException as exc:
            if not failure_class:
                failure_class = (
                    "cancelled"
                    if isinstance(exc, asyncio.CancelledError)
                    else "unexpected_error"
                )
            await _terminate(self.proc)
            await asyncio.gather(io_task, return_exceptions=True)
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            append_failure_record(exc, failure_class)
            raise
        finally:
            if not terminal_task.done():
                terminal_task.cancel()
            await asyncio.gather(terminal_task, return_exceptions=True)
            for task in (stdout_task, stderr_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            self._terminal_signal = None
            self._terminal_error = ""
            self._terminal_metadata = {}

        cleaned_stderr = clean(stderr.decode("utf-8", errors="replace"), (secret,))
        if cleaned_stderr:
            append_jsonl(stream_path, {"type": "stderr", "text": cleaned_stderr[-8000:]})
        if malformed:
            append_jsonl(stream_path, {"type": "malformed", "lines": malformed})

        result_session = session_id
        texts: list[str] = []
        tools: list[dict] = []
        usage: list[dict] = []
        cost = 0.0
        errors: list[str] = []
        for event in events:
            candidate = event.get("sessionID") or event.get("session_id")
            if isinstance(candidate, str) and candidate:
                result_session = candidate
            event_type = event.get("type")
            part = event.get("part") if isinstance(event.get("part"), dict) else {}
            if event_type == "text" and isinstance(part.get("text"), str):
                texts.append(part["text"])
            elif event_type == "tool_use":
                state = part.get("state") if isinstance(part.get("state"), dict) else {}
                metadata = state.get("metadata") if isinstance(state.get("metadata"), dict) else {}
                status = str(state.get("status", ""))
                tools.append({
                    "id": part.get("callID") or part.get("id") or f"tool-{len(tools)+1}",
                    "name": part.get("tool") or "tool",
                    "input": state.get("input") if isinstance(state.get("input"), dict) else {},
                    "output": tool_state_text(state),
                    "is_error": status in {"error", "failed"} or bool(metadata.get("exit")),
                    "status": status,
                })
            elif event_type == "step_finish":
                tokens = part.get("tokens") if isinstance(part.get("tokens"), dict) else {}
                usage.append(tokens)
                try:
                    cost += float(part.get("cost") or 0)
                except (TypeError, ValueError):
                    pass
            elif event_type == "error":
                errors.append(str(event.get("error") or event.get("message") or event)[:1000])

        assistant_text, text_metadata = _select_assistant_text(texts)
        duration = time.time() - started
        call_record = {
            "at": time.time(),
            "role": self.role,
            "route": self.route,
            "effort": self.effort,
            "transport_route": transport_route,
            "runner": "opencode",
            "gateway": "openclaude",
            "session_id": result_session,
            "resumed": bool(session_id),
            "duration_s": round(duration, 3),
            "returncode": returncode,
            "event_count": len(events),
            "tool_count": len(tools),
            "usage": usage,
            "cost": cost,
            "prompt_sha256": prompt_hash,
            "stdout_sha256": hashlib.sha256(cleaned_stdout.encode("utf-8")).hexdigest(),
            "stderr_present": bool(cleaned_stderr),
            "ok": not returncode and not errors and bool(texts),
            **text_metadata,
        }
        gateway_events = gateway.drain_events()
        call_record["failover_count"] = sum(
            1 for event in gateway_events
            if event.get("type") == "openclaude_notice"
            and "continuing on key" in str(event.get("message") or "")
        )
        if returncode:
            detail = cleaned_stderr[-1000:] or (
                errors[-1] if errors else "no error detail"
            )
            call_record.update({
                "error_class": "process_exit",
                "error_type": "ProviderError",
                "error_message": clean(detail, (secret,))[:1000],
            })
        elif errors:
            call_record.update({
                "error_class": "provider_event_error",
                "error_type": "ProviderError",
                "error_message": clean(errors[-1], (secret,))[:1000],
            })
        elif not texts:
            call_record.update({
                "error_class": "empty_response",
                "error_type": "ProviderError",
                "error_message": f"{self.role} OpenCode returned no final text.",
            })
        append_jsonl(self.transcripts / "provider-calls.jsonl", call_record)
        if returncode:
            raise ProviderError(f"{self.role} OpenCode exited with {returncode}: {detail}")
        if errors:
            raise ProviderError(f"{self.role} OpenCode error: {errors[-1]}")
        if not texts:
            raise ProviderError(f"{self.role} OpenCode returned no final text.")
        return OpenCodeResult(
            text=assistant_text,
            session_id=result_session,
            events=events,
            tools=tools,
            usage=usage,
            duration_s=duration,
            cost=cost,
            stderr=cleaned_stderr,
            returncode=returncode,
        )

    async def cancel(self) -> None:
        if self.proc is not None:
            await _terminate(self.proc)
        if self.gateway is not None:
            await self.gateway.close()
            self.gateway = None


class CodexValidator:
    """A fresh, tool-disabled GPT-6 Astra process for each requested review."""

    def __init__(self, workspace: Path, target_slug: str):
        self.workspace = workspace.resolve()
        self.target_slug = target_slug
        self.transcripts = private_dir(self.workspace / "transcripts")
        self.proc: Optional[asyncio.subprocess.Process] = None

    async def validate(self, prompt: str, schema: dict, *, timeout: float = 900) -> dict:
        binary = config.require_binary("codex")
        runtime = private_dir(
            config.PROVIDER_DIR / self.target_slug
            / f"validator-call-{os.getpid()}-{time.time_ns()}"
        )
        schema_path = runtime / "schema.json"
        answer_path = runtime / "answer.json"
        atomic_json(schema_path, schema)
        answer_path.unlink(missing_ok=True)
        argv = [
            binary, "exec", "--ignore-user-config", "--ignore-rules", "--ephemeral",
            "--skip-git-repo-check", "--sandbox", "read-only",
            "--model", config.VALIDATOR_MODEL, "--json", "--color", "never",
            "--output-schema", str(schema_path), "--output-last-message", str(answer_path),
            "-c", f'model_reasoning_effort="{config.VALIDATOR_EFFORT}"',
            "-c", 'approval_policy="never"', "-c", 'web_search="disabled"',
            "-c", "project_doc_max_bytes=0",
        ]
        for feature in (
            "shell_tool", "unified_exec", "multi_agent", "apps", "plugins",
            "computer_use", "skill_search", "shell_snapshot", "view_image",
        ):
            argv += ["--disable", feature]
        argv.append("-")
        started = time.time()
        self.proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(runtime),
            env=_codex_child_environment(),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        assert self.proc.stdin and self.proc.stdout and self.proc.stderr
        self.proc.stdin.write(prompt.encode("utf-8"))
        await self.proc.stdin.drain()
        self.proc.stdin.close()
        try:
            stdout, stderr = await asyncio.wait_for(
                asyncio.gather(self.proc.stdout.read(), self.proc.stderr.read()), timeout=timeout
            )
            returncode = await asyncio.wait_for(self.proc.wait(), timeout=10)
        except asyncio.TimeoutError as exc:
            await _terminate(self.proc)
            raise ProviderError(f"Astra validation timed out after {timeout:g}s.") from exc
        cleaned_out = clean(stdout.decode("utf-8", errors="replace"))
        cleaned_err = clean(stderr.decode("utf-8", errors="replace"))
        for line in cleaned_out.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                event = {"type": "malformed", "text": line[:500]}
            append_jsonl(self.transcripts / "validator.codex.events.jsonl", event)
            item = event.get("item", {}) if isinstance(event, dict) else {}
            if isinstance(item, dict) and item.get("type") in {
                "command_execution", "mcp_tool_call", "web_search", "file_change"
            }:
                raise ProviderError("Astra attempted tool use; validation was rejected.")
        append_jsonl(self.transcripts / "provider-calls.jsonl", {
            "at": time.time(), "role": "validator", "route": config.VALIDATOR_MODEL,
            "effort": config.VALIDATOR_EFFORT, "duration_s": round(time.time() - started, 3),
            "returncode": returncode, "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
            "stdout_sha256": hashlib.sha256(cleaned_out.encode()).hexdigest(),
            "stderr_present": bool(cleaned_err),
        })
        if returncode:
            raise ProviderError(f"Astra exited with {returncode}: {cleaned_err[-1000:]}")
        if not answer_path.is_file() or answer_path.stat().st_size > 1_000_000:
            raise ProviderError("Astra did not produce a bounded structured verdict.")
        try:
            value = json.loads(answer_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ProviderError("Astra verdict was not valid JSON.") from exc
        return value

    async def cancel(self) -> None:
        if self.proc is not None:
            await _terminate(self.proc)
