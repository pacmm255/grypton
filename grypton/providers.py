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


MAX_STREAM_BYTES = 16_000_000
MCP_TIMEOUT_MS = 120_000
_OPENCODE_VERSION: Optional[str] = None
_CONTROL = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|"
    r"[\x00-\x08\x0b-\x1f\x7f-\x9f]"
)


class ProviderError(RuntimeError):
    pass


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


def opencode_credential(provider: str) -> dict:
    path = _host_xdg("DATA", ".local/share") / "opencode/auth.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8")).get(provider, {})
    except (OSError, ValueError, AttributeError) as exc:
        raise ProviderError(
            f"OpenCode connector {provider!r} is unavailable; connect it in OpenCode."
        ) from exc
    if value.get("type") != "api" or not isinstance(value.get("key"), str) or not value["key"]:
        raise ProviderError(f"OpenCode connector {provider!r} has no API credential.")
    if provider == "opencode-go" and Path("/root/open").is_file():
        try:
            supplied = {
                line.strip()
                for line in Path("/root/open").read_text(encoding="utf-8").splitlines()
                if re.fullmatch(r"[A-Za-z0-9._-]{20,}", line.strip())
            }
        except OSError as exc:
            raise ProviderError("The supplied OpenCode Go key file cannot be read.") from exc
        if value["key"] not in supplied:
            raise ProviderError("The OpenCode Go connector does not match a key in /root/open.")
    return {"type": "api", "key": value["key"]}


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

        # Kraude needs a shell for local parsing and evidence work, but native
        # network clients bypass Grypton's scope guard and immutable flow
        # capture. OpenCode evaluates Bash permissions per parsed command, so
        # deny the network executables while retaining ordinary local shell
        # commands. The corresponding operations remain available through the
        # scoped grypton_* MCP tools.
        bash = {"*": "allow"}
        for executable in (
            "curl", "wget", "httpx", "nmap", "subfinder", "dnsx",
            "naabu", "masscan", "nc", "ncat", "netcat", "telnet",
            "ftp", "sftp", "scp", "ssh",
        ):
            bash[f"{executable} *"] = "deny"
            bash[f"*/{executable} *"] = "deny"
        bash["openssl s_client *"] = "deny"
        bash["*/openssl s_client *"] = "deny"

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
            external_directory = {
                **{str(path / "*"): "allow" for path in allowed_external},
                "*": "deny",
            }

        return {
            "*": "allow",
            "bash": bash,
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

    def _environment(self) -> tuple[dict, str]:
        auth = opencode_credential(self.provider)
        for kind in ("config", "data", "cache", "state"):
            private_dir(self.runtime / kind)
        _seed_opencode_dependencies(self.runtime / "config/opencode")
        atomic_json(self.runtime / "data/opencode/auth.json", {self.provider: auth})
        source_catalog = _host_xdg("CACHE", ".cache") / "opencode/models.json"
        catalog_target = self.runtime / "cache/opencode/models.json"
        if source_catalog.is_file() and not catalog_target.is_file():
            try:
                catalog = json.loads(source_catalog.read_text(encoding="utf-8"))
                atomic_json(catalog_target, {self.provider: catalog[self.provider]})
            except (OSError, ValueError, KeyError):
                pass

        permissions = self._permissions(
            self.allow_tools,
            self.workspace if self.allow_tools else None,
            self.transport_workspace if self.allow_tools else None,
        )
        inline = {
            "$schema": "https://opencode.ai/config.json",
            # Grypton already records immutable request/response flows, append-only
            # ledgers, and full provider event streams. OpenCode's separate Git
            # snapshot refresh can deadlock before the first model event when
            # several isolated sessions initialize concurrently, so disable that
            # redundant layer for provider transports.
            "snapshot": False,
            "enabled_providers": [self.provider],
            "model": self.route,
            "small_model": self.route,
            "default_agent": f"grypton-{self.role}",
            "permission": permissions,
            "share": "disabled",
            "autoupdate": False,
            "plugin": [],
            "agent": {
                f"grypton-{self.role}": {
                    "description": f"Grypton {self.role}",
                    "mode": "primary",
                    "model": self.route,
                    "prompt": self.agent_prompt,
                    "permission": permissions,
                    # Yield back to Kryptex often enough for it to correct course
                    # while still leaving room for a useful autonomous burst.
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
                    # Network probes retain their own bounded timeouts.  This
                    # ceiling must be longer so OpenCode does not abort a
                    # healthy MCP call first and report an empty tool error.
                    "timeout": MCP_TIMEOUT_MS,
                    "environment": {
                        "GRYPTON_HOME": str(config.GRYPTON_HOME),
                        "GRYPTON_TARGET": self.target_slug,
                        "KRYPTON_HOME": str(config.GRYPTON_HOME),
                        "KRYPTON_TARGET": self.target_slug,
                        # The state home may be distinct from the checkout or
                        # installed package root.  The MCP subprocess imports
                        # Grypton's code from SOURCE_ROOT while it writes
                        # engagement data under GRYPTON_HOME.
                        "PYTHONPATH": str(config.SOURCE_ROOT),
                    },
                }
            }

        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith((
                "OPENCODE_", "OPENAI_", "ANTHROPIC_", "ZAI_", "ZHIPU_"
            ))
        }
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
            # OpenCode 1.18.x can still enter the repository-copy path while
            # selecting a session even when snapshot tracking is disabled.
            # Provider sessions use Grypton's immutable logs and work directly
            # in their engagement workspace, so that copy is unnecessary.
            "OPENCODE_EXPERIMENTAL_DISABLE_COPY_ON_SELECT": "true",
            "OPENCODE_PERMISSION": json.dumps(permissions),
            # Engagement workspaces live below the Grypton source checkout.
            # Prevent Git/OpenCode from treating the whole source repository as
            # the model's project; that caused startup scans and snapshot work
            # across every runtime when three engagements launched together.
            "GIT_CEILING_DIRECTORIES": str(config.GRYPTON_HOME),
            "GRYPTON_HOME": str(config.GRYPTON_HOME),
            "GRYPTON_TARGET": self.target_slug,
            "GRYPTON_ENGAGEMENT_DIR": str(self.workspace),
            "KRYPTON_HOME": str(config.GRYPTON_HOME),
            "KRYPTON_TARGET": self.target_slug,
            "PATH": f"{config.BIN_DIR}:{env.get('PATH', '')}",
            "NO_COLOR": "1",
        })
        # Preserve importability for the local MCP child even when an operator
        # directs runtime state to another filesystem location.
        source_path = str(config.SOURCE_ROOT)
        inherited_pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = source_path + (
            os.pathsep + inherited_pythonpath if inherited_pythonpath else ""
        )
        return env, auth["key"]

    async def call(
        self,
        prompt: str,
        *,
        session_id: str = "",
        timeout: float = 1800,
        title: str = "",
    ) -> OpenCodeResult:
        binary = config.require_binary("opencode")
        env, secret = self._environment()
        argv = [
            binary, "run", "--pure", "--format", "json",
            "--model", self.route, "--variant", self.effort,
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
        try:
            cleaned_stdout, stderr, returncode = await asyncio.wait_for(
                asyncio.gather(stdout_task, stderr_task, self.proc.wait()), timeout=timeout
            )
        except asyncio.TimeoutError as exc:
            await _terminate(self.proc)
            raise ProviderError(f"{self.role} OpenCode call timed out after {timeout:g}s.") from exc
        except BaseException:
            await _terminate(self.proc)
            raise
        finally:
            for task in (stdout_task, stderr_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

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

        duration = time.time() - started
        call_record = {
            "at": time.time(),
            "role": self.role,
            "route": self.route,
            "effort": self.effort,
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
        }
        append_jsonl(self.transcripts / "provider-calls.jsonl", call_record)
        if returncode:
            detail = cleaned_stderr[-1000:] or (errors[-1] if errors else "no error detail")
            raise ProviderError(f"{self.role} OpenCode exited with {returncode}: {detail}")
        if errors:
            raise ProviderError(f"{self.role} OpenCode error: {errors[-1]}")
        if not texts:
            raise ProviderError(f"{self.role} OpenCode returned no final text.")
        return OpenCodeResult(
            text="\n".join(texts).strip(),
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
            env={key: value for key, value in os.environ.items() if not key.startswith("OPENCODE_")},
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
