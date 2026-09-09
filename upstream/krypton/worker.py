"""Kraude — the patched Claude Code worker driver.

Drives a single, continuous ``claude`` process in bidirectional ``stream-json``
mode (R2–R4): one resumed session for the entire hunt, Opus 4.8 @ max effort,
auto-compaction handled by Claude itself. The engine feeds it one directive per
turn and reads back the full turn (assistant text + tool calls + result).

Robustness:
  * Custom unbounded line reader — Claude emits multi-MB JSONL lines (inline tool
    results) that blow past asyncio's default 64 KB StreamReader limit.
  * Tolerant parsing — malformed/partial lines are skipped, never fatal.
  * Crash-resilient — if the process dies, ``ensure_started`` re-spawns
    ``claude --resume <same uuid>``; continuity is preserved on disk.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, Optional

from . import config

EventCb = Optional[Callable[[dict], None]]
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


class WorkerError(RuntimeError):
    pass


@dataclass
class TurnResult:
    assistant_text: str
    tool_uses: list[dict]
    result: dict
    is_error: bool = False
    num_turns: int = 0
    duration_s: float = 0.0
    cost_usd: float = 0.0


@dataclass
class WorkerSpec:
    """Everything needed to launch the worker for a target."""

    session_uuid: str
    cwd: Path
    system_prompt: str
    mcp_config_path: Optional[Path] = None
    settings_path: Optional[Path] = None
    add_dirs: tuple[str, ...] = ()
    model: str = config.WORKER_MODEL
    effort: str = config.WORKER_EFFORT
    extra_env: dict = field(default_factory=dict)
    log_path: Optional[Path] = None
    turn_timeout_s: int = 3600


async def _read_lines(stream: asyncio.StreamReader):
    """Yield complete lines (bytes, newline-stripped) with no length limit."""
    buf = bytearray()
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            if buf:
                yield bytes(buf)
            return
        buf.extend(chunk)
        while True:
            nl = buf.find(b"\n")
            if nl < 0:
                break
            line = bytes(buf[:nl])
            del buf[: nl + 1]
            yield line


class KraudeWorker:
    """Async driver for one continuous Claude Code session."""

    def __init__(self, spec: WorkerSpec, on_event: EventCb = None):
        self.spec = spec
        self.on_event = on_event
        self.proc: Optional[asyncio.subprocess.Process] = None
        self._queue: asyncio.Queue = asyncio.Queue()
        self._reader_task: Optional[asyncio.Task] = None
        self._stderr_task: Optional[asyncio.Task] = None
        self._log = None
        self._started = False
        self.session_id: str = spec.session_uuid

    # ---- process lifecycle ----------------------------------------------

    def _build_argv(self) -> list[str]:
        claude = config.require_binary("claude")
        argv = [
            claude, "-p",
            "--input-format", "stream-json",
            "--output-format", "stream-json",
            "--verbose",
            "--include-partial-messages",
            "--replay-user-messages",
            "--resume", self.spec.session_uuid,
            "--model", self.spec.model,
            "--effort", self.spec.effort,
            "--permission-mode", "bypassPermissions",
            "--dangerously-skip-permissions",
            "--setting-sources", "project,local",
            "--append-system-prompt", self.spec.system_prompt,
        ]
        if self.spec.settings_path and self.spec.settings_path.exists():
            argv += ["--settings", str(self.spec.settings_path)]
        if self.spec.mcp_config_path and self.spec.mcp_config_path.exists():
            argv += ["--mcp-config", str(self.spec.mcp_config_path)]
        for d in self.spec.add_dirs:
            argv += ["--add-dir", d]
        return argv

    def session_jsonl_path(self) -> Path:
        return (config.CLAUDE_PROJECTS_DIR
                / config.encode_project_dir(self.spec.cwd)
                / f"{self.spec.session_uuid}.jsonl")

    async def rewind_idle_tail(self) -> int:
        """Close the worker process and DEEP-strip the entire tail of consecutive
        idle (no-tool-use) turns from its session JSONL — back to the last
        productive turn. This removes the whole anchored "we're done" refusal
        streak from history, not just the latest refusal. The next ``run_turn``
        restarts the worker on the cleaned session. Returns the number of pairs
        removed (0 if the most recent turn was already productive)."""
        from . import sessions
        await self.aclose()
        return sessions.rewind_idle_tail(self.session_jsonl_path())

    async def start(self) -> None:
        if self._started:
            return
        # drop any stale events left by a previous process (e.g. after rewind)
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        self.spec.cwd.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ)
        # Avoid recursive Claude-in-Claude env confusion in the child.
        for k in ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_SESSION_ID",
                  "CLAUDE_CODE_EXECPATH"):
            env.pop(k, None)
        # Claude refuses --dangerously-skip-permissions / bypassPermissions as root
        # unless it believes it is sandboxed. This is a dedicated root VM for
        # authorized testing, so assert the sandbox marker (makes Krypton work from
        # any root shell, not just one that already had it set).
        env["IS_SANDBOX"] = "1"
        env.update(self.spec.extra_env)
        if self.spec.log_path:
            self.spec.log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log = self.spec.log_path.open("ab")

        self.proc = await asyncio.create_subprocess_exec(
            *self._build_argv(),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(self.spec.cwd),
            env=env,
        )
        self._reader_task = asyncio.create_task(self._pump_stdout())
        self._stderr_task = asyncio.create_task(self._pump_stderr())
        self._started = True

    async def ensure_started(self) -> None:
        """(Re)start the worker if it isn't running — preserves session continuity."""
        if self._started and self.proc and self.proc.returncode is None:
            return
        self._started = False
        await self.start()

    async def _pump_stdout(self) -> None:
        assert self.proc and self.proc.stdout
        async for raw in _read_lines(self.proc.stdout):
            if self._log:
                self._log.write(raw + b"\n")
            if not raw.strip():
                continue
            try:
                evt = json.loads(raw.decode("utf-8", "replace"))
            except ValueError:
                continue
            await self._queue.put(evt)
        await self._queue.put({"type": "__eof__"})

    async def _pump_stderr(self) -> None:
        assert self.proc and self.proc.stderr
        async for raw in _read_lines(self.proc.stderr):
            if self._log:
                self._log.write(b"[stderr] " + raw + b"\n")

    # ---- driving a turn --------------------------------------------------

    async def _send(self, message: dict) -> None:
        assert self.proc and self.proc.stdin
        line = (json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8")
        self.proc.stdin.write(line)
        await self.proc.stdin.drain()

    async def run_turn(self, text: str) -> TurnResult:
        """Send one user directive and collect the full worker turn."""
        await self.ensure_started()
        # ROOT-CAUSE FIX (2026-07-04): drop anything queued before this directive.
        # On session load, Claude Code (-p, stream-json, --resume) emits a startup
        # `result` event with num_turns=0 BEFORE any user input. The engine
        # eager-starts the worker (start() long before the first run_turn), so that
        # stale result is already in the queue; reading it as this turn's result
        # made every turn return 0 tool calls -> the engine reported "Kraude was
        # IDLE" forever. Draining here discards that startup init/result noise.
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        start = time.time()
        await self._send({
            "type": "user",
            "message": {"role": "user",
                        "content": [{"type": "text", "text": text}]},
        })

        assistant_chunks: list[str] = []
        tool_uses: list[dict] = []
        result_evt: dict = {}
        turn_started = False   # True once THIS turn's own activity begins

        while True:
            try:
                evt = await asyncio.wait_for(self._queue.get(), timeout=self.spec.turn_timeout_s)
            except asyncio.TimeoutError:
                raise WorkerError(f"Worker turn exceeded {self.spec.turn_timeout_s}s without a result")

            etype = evt.get("type")
            if etype == "__eof__":
                rc = self.proc.returncode if self.proc else None
                raise WorkerError(f"Worker process ended mid-turn (exit={rc})")

            if self.on_event:
                try:
                    self.on_event(evt)
                except Exception:
                    pass

            # `--replay-user-messages` echoes our directive back as a `user`
            # event, then real assistant output follows. A `result` arriving
            # before any of that is a stale startup result that slipped past the
            # drain above (race between the drain and the queued event) — ignore
            # it so it can't be mistaken for this turn's outcome.
            if etype in ("user", "assistant"):
                turn_started = True

            if etype == "system":
                self.session_id = evt.get("session_id", self.session_id)
            elif etype == "assistant":
                content = (evt.get("message") or {}).get("content", [])
                for block in content if isinstance(content, list) else []:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "text" and block.get("text"):
                        assistant_chunks.append(block["text"])
                    elif block.get("type") == "tool_use":
                        tool_uses.append({"name": block.get("name"),
                                          "input": block.get("input")})
            elif etype == "result":
                if not turn_started:
                    continue   # stale pre-directive / startup result — skip
                result_evt = evt
                break

        return TurnResult(
            assistant_text="\n".join(assistant_chunks).strip(),
            tool_uses=tool_uses,
            result=result_evt,
            is_error=bool(result_evt.get("is_error")),
            num_turns=int(result_evt.get("num_turns") or 0),
            duration_s=time.time() - start,
            cost_usd=float(result_evt.get("total_cost_usd") or 0.0),
        )

    async def aclose(self) -> None:
        if self.proc and self.proc.returncode is None:
            try:
                if self.proc.stdin:
                    self.proc.stdin.close()
            except Exception:
                pass
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=10)
            except (asyncio.TimeoutError, Exception):
                try:
                    self.proc.kill()
                except Exception:
                    pass
        for t in (self._reader_task, self._stderr_task):
            if t:
                t.cancel()
        if self._log:
            try:
                self._log.close()
            except Exception:
                pass
        self._started = False


class CodexWorker:
    """Async adapter that runs the worker role through ``codex exec``.

    Unlike ``KraudeWorker`` there is no long-lived child process. Each turn is a
    ``codex exec`` invocation, resumed on the captured Codex thread id when
    possible. The adapter translates Codex JSON events into the small subset of
    Claude stream events the engine already understands: assistant text,
    Bash-like tool calls, and tool results.
    """

    def __init__(self, spec: WorkerSpec, on_event: EventCb = None):
        self.spec = spec
        self.on_event = on_event
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.session_id: str = spec.session_uuid
        self._started = False
        self._log = None

    # ---- process lifecycle ----------------------------------------------

    @staticmethod
    def _codex_env() -> dict:
        """Match KryptexManager's Codex auth behavior without importing it."""
        env = dict(os.environ)
        if env.get("OPENAI_API_KEY"):
            return env
        authp = config.CODEX_HOME / "auth.json"
        try:
            if authp.exists():
                data = json.loads(authp.read_text())
                if data.get("auth_mode") == "apikey" and data.get("OPENAI_API_KEY"):
                    env["OPENAI_API_KEY"] = data["OPENAI_API_KEY"]
        except Exception:
            pass
        return env

    def _build_argv(self, last_file: Optional[Path] = None) -> list[str]:
        codex = config.require_binary("codex")
        argv = [codex, "exec"]
        resuming = bool(self.session_id)
        if resuming:
            # `codex exec resume` does not accept -C/--add-dir; it resumes the
            # cwd and writable roots recorded on the first worker turn.
            argv += ["resume", self.session_id]
        argv += [
            "--json",
            "--skip-git-repo-check",
            "--dangerously-bypass-approvals-and-sandbox",
            "-c", f'model_reasoning_effort="{self.spec.effort}"',
        ]
        if not resuming:
            argv += ["-C", str(self.spec.cwd)]
            for d in self.spec.add_dirs:
                argv += ["--add-dir", d]
        if self.spec.model:
            argv += ["-m", self.spec.model]
        if last_file is not None:
            argv += ["-o", str(last_file)]
        argv += ["-"]
        return argv

    async def start(self) -> None:
        if self._started:
            return
        self.spec.cwd.mkdir(parents=True, exist_ok=True)
        if self.spec.log_path:
            self.spec.log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log = self.spec.log_path.open("ab")
        self._started = True
        self._emit({
            "type": "system",
            "subtype": "init",
            "cwd": str(self.spec.cwd),
            "session_id": self.session_id,
            "tools": ["codex.exec", "shell", "krypton-tool"],
            "mcp_servers": [{"name": "krypton-tool", "status": "cli"}],
            "model": self.spec.model,
            "permissionMode": "danger-full-access",
        })

    async def ensure_started(self) -> None:
        if not self._started:
            await self.start()

    async def rewind_idle_tail(self) -> int:
        """Drop the Codex thread id after an idle turn.

        Claude can surgically trim its JSONL tail; Codex session storage is not
        managed by Krypton, so the practical equivalent is to start the next
        turn on a fresh thread with the same workspace files.
        """
        await self.aclose()
        self.session_id = ""
        self.spec.session_uuid = ""
        return 0

    async def aclose(self) -> None:
        if self.proc and self.proc.returncode is None:
            try:
                self.proc.kill()
            except Exception:
                pass
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=10)
            except Exception:
                pass
        if self._log:
            try:
                self._log.close()
            except Exception:
                pass
            self._log = None
        self._started = False

    # ---- driving a turn --------------------------------------------------

    def _build_prompt(self, text: str) -> str:
        target_slug = (self.spec.extra_env or {}).get("KRYPTON_TARGET", "")
        tool_bin = str(config.BIN_DIR / "krypton-tool")
        tool_prefix = f"{tool_bin} --target {target_slug}" if target_slug else tool_bin
        return (
            self.spec.system_prompt
            + "\n\n=== FULL-CODEX WORKER MODE ===\n"
              "You are the Codex-backed Krypton worker for this target. Execute "
              "commands directly when they are needed; do not describe commands "
              "instead of running them. You do not have Claude MCP tool names in "
              "this backend. Use the Krypton CLI tool for ledger writes:\n"
            + f"- Surface: `{tool_prefix} surface --kind endpoint --item <item> --detail <detail>`\n"
            + f"- Tested technique: `{tool_prefix} tested --surface <surface> --technique <technique> --result <result> --evidence <evidence>`\n"
            + f"- Finding: `{tool_prefix} finding --title <title> --severity <severity> --class <class> --surface <surface> --description <description> --poc <poc> --evidence <evidence>`\n"
              "Read and update the workspace files in the current directory. "
              "Obey scope-rules.md and the binding constraints from the system "
              "prompt. End productive turns with real command/tool activity and "
              "ledger updates, not prose-only summaries.\n\n"
              "=== KRYPTEX DIRECTIVE ===\n"
            + text
        )

    async def run_turn(self, text: str) -> TurnResult:
        await self.ensure_started()
        start = time.time()
        assistant_chunks: list[str] = []
        tool_uses: list[dict] = []
        seen_tools: set[str] = set()
        result_evt: dict = {}
        errors: list[str] = []

        last_file = None
        if self.spec.log_path:
            last_file = self.spec.log_path.parent / f"worker.codex.last-{int(time.time() * 1000)}.txt"

        prompt = self._build_prompt(text)
        self._emit({
            "type": "user",
            "message": {"role": "user", "content": text},
            "session_id": self.session_id,
        })

        env = self._codex_env()
        env["PATH"] = f"{config.BIN_DIR}:{env.get('PATH', '')}"
        env.update(self.spec.extra_env or {})
        argv = self._build_argv(last_file=last_file)
        try:
            self.proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.spec.cwd),
                env=env,
            )
        except FileNotFoundError as e:
            raise WorkerError(f"codex not found: {e}") from e

        try:
            assert self.proc.stdin
            self.proc.stdin.write(prompt.encode("utf-8"))
            await self.proc.stdin.drain()
            self.proc.stdin.close()
        except Exception:
            pass

        async def pump_stdout() -> None:
            assert self.proc and self.proc.stdout
            async for raw in _read_lines(self.proc.stdout):
                self._write_raw(raw)
                if not raw.strip():
                    continue
                try:
                    evt = json.loads(raw.decode("utf-8", "replace"))
                except ValueError:
                    continue
                self._capture_session_id(evt)
                self._handle_codex_event(evt, assistant_chunks, tool_uses,
                                         seen_tools, result_evt, errors)

        try:
            await asyncio.wait_for(pump_stdout(), timeout=self.spec.turn_timeout_s)
            await asyncio.wait_for(self.proc.wait(), timeout=30)
        except asyncio.TimeoutError as e:
            try:
                self.proc.kill()
            except Exception:
                pass
            raise WorkerError(f"Codex worker turn exceeded {self.spec.turn_timeout_s}s") from e

        try:
            stderr = await asyncio.wait_for(self.proc.stderr.read(), timeout=5) \
                if self.proc.stderr else b""
        except Exception:
            stderr = b""
        if stderr:
            self._write_raw(b"[stderr] " + stderr.replace(b"\n", b"\n[stderr] "))

        if not assistant_chunks and last_file and last_file.exists():
            try:
                text_out = last_file.read_text(encoding="utf-8", errors="replace").strip()
                if text_out:
                    assistant_chunks.append(text_out)
            except OSError:
                pass
        if last_file:
            try:
                last_file.unlink(missing_ok=True)
            except OSError:
                pass

        rc = self.proc.returncode if self.proc else 0
        is_error = bool(errors) or bool(rc)
        if is_error and not assistant_chunks:
            err = errors[-1] if errors else stderr.decode("utf-8", "replace")[-500:]
            assistant_chunks.append(err or f"codex worker exited with rc={rc}")

        result = dict(result_evt) if result_evt else {}
        result.setdefault("session_id", self.session_id)
        result.setdefault("is_error", is_error)
        if errors:
            result.setdefault("error", errors[-1])
        if rc:
            result.setdefault("returncode", rc)

        return TurnResult(
            assistant_text="\n".join(assistant_chunks).strip(),
            tool_uses=tool_uses,
            result=result,
            is_error=is_error,
            num_turns=1,
            duration_s=time.time() - start,
            cost_usd=0.0,
        )

    # ---- event translation ----------------------------------------------

    def _write_raw(self, raw: bytes) -> None:
        if not self._log:
            return
        try:
            self._log.write(raw + b"\n")
            self._log.flush()
        except Exception:
            pass

    def _emit(self, evt: dict) -> None:
        self._write_raw(json.dumps(evt, ensure_ascii=False).encode("utf-8"))
        if self.on_event:
            try:
                self.on_event(evt)
            except Exception:
                pass

    def _capture_session_id(self, evt: dict) -> None:
        for key in ("thread_id", "session_id"):
            value = evt.get(key)
            if isinstance(value, str) and _UUID_RE.fullmatch(value):
                self.session_id = value
                self.spec.session_uuid = value
                return
        if self.session_id:
            return
        try:
            payload = json.dumps(evt)
        except (TypeError, ValueError):
            return
        match = _UUID_RE.search(payload)
        if match:
            self.session_id = match.group(0)
            self.spec.session_uuid = self.session_id

    @staticmethod
    def _error_text(evt: dict) -> str:
        msg = evt.get("message")
        if msg:
            return str(msg)
        err = evt.get("error")
        if isinstance(err, dict):
            return str(err.get("message") or err)
        if err:
            return str(err)
        return ""

    def _emit_tool_use(self, tool_id: str, command: str,
                       tool_uses: list[dict], seen_tools: set[str]) -> None:
        if tool_id in seen_tools:
            return
        seen_tools.add(tool_id)
        block = {"type": "tool_use", "id": tool_id, "name": "Bash",
                 "input": {"command": command}}
        tool_uses.append({"name": "Bash", "input": {"command": command}})
        self._emit({
            "type": "assistant",
            "message": {"role": "assistant", "content": [block]},
            "session_id": self.session_id,
        })

    def _emit_tool_result(self, tool_id: str, output: str, is_error: bool) -> None:
        self._emit({
            "type": "user",
            "message": {
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": output,
                    "is_error": is_error,
                }],
            },
            "session_id": self.session_id,
        })

    def _emit_text(self, text: str, assistant_chunks: list[str]) -> None:
        if not text:
            return
        assistant_chunks.append(text)
        self._emit({
            "type": "stream_event",
            "event": {
                "type": "content_block_delta",
                "delta": {"type": "text_delta", "text": text},
            },
            "session_id": self.session_id,
        })
        self._emit({
            "type": "assistant",
            "message": {"role": "assistant",
                        "content": [{"type": "text", "text": text}]},
            "session_id": self.session_id,
        })

    def _handle_codex_event(self, evt: dict, assistant_chunks: list[str],
                            tool_uses: list[dict], seen_tools: set[str],
                            result_evt: dict, errors: list[str]) -> None:
        etype = evt.get("type")
        if etype in ("error", "turn.failed", "thread.error"):
            err = self._error_text(evt)
            if err:
                errors.append(err)
            return
        if etype == "turn.completed":
            result_evt.clear()
            result_evt.update(evt)
            return

        item = evt.get("item") if isinstance(evt.get("item"), dict) else None
        if not item:
            return
        itype = item.get("type")
        if itype == "agent_message" and etype == "item.completed":
            self._emit_text(str(item.get("text") or ""), assistant_chunks)
        elif itype == "command_execution":
            tool_id = str(item.get("id") or f"codex-tool-{len(seen_tools) + 1}")
            command = str(item.get("command") or "")
            if command:
                self._emit_tool_use(tool_id, command, tool_uses, seen_tools)
            if etype == "item.completed":
                output = str(item.get("aggregated_output") or "")
                exit_code = item.get("exit_code")
                self._emit_tool_result(tool_id, output, exit_code not in (0, None))
