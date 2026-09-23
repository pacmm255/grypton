"""Kraude: a persistent, selectable worker driven through OpenCode/OpenClaude."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import time
from typing import Callable, Optional

from . import config
from .providers import OpenCodeClient, ProviderError, tool_state_text


EventCb = Optional[Callable[[dict], None]]


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
    session_uuid: str
    cwd: Path
    system_prompt: str
    model: str = config.WORKER_MODEL
    effort: str = config.WORKER_EFFORT
    extra_env: dict = field(default_factory=dict)
    log_path: Optional[Path] = None
    turn_timeout_s: int = 1800


class OpenCodeWorker:
    """Resume one OpenCode session ID across every engine turn."""

    def __init__(self, spec: WorkerSpec, on_event: EventCb = None):
        self.spec = spec
        self.on_event = on_event
        self.session_id = spec.session_uuid or ""
        self._started = False
        self.client = self._new_client()

    def _new_client(self) -> OpenCodeClient:
        """Build the transport for the current role selection.

        Model changes intentionally create a fresh provider session. Grypton's
        durable ledgers remain the source of engagement memory, while an old
        vendor/model transcript is not replayed into an incompatible route.
        """
        slug = (
            self.spec.extra_env.get("GRYPTON_TARGET")
            or self.spec.extra_env.get("KRYPTON_TARGET")
            or self.spec.cwd.name
        )
        return OpenCodeClient(
            role="worker",
            route=self.spec.model or config.WORKER_MODEL,
            effort=self.spec.effort or config.WORKER_EFFORT,
            workspace=self.spec.cwd,
            target_slug=slug,
            allow_tools=True,
            agent_prompt=(
                "You are Kraude, the hands-on worker in a persistent Grypton engagement. "
                f"Your selected OpenClaude route is {self.spec.model} at "
                f"{self.spec.effort} effort. "
                "Use tools and produce observable progress. Read engagement ledgers through "
                "the grypton_read_doc MCP tool, then obey scope-rules.md exactly. "
                "Record surface, tested techniques, and findings with the grypton MCP "
                "tools. Resolve routine local blockers yourself. Never inspect or reveal "
                "provider credentials. End with a concise factual summary.\n\n"
                + self.spec.system_prompt
            ),
            event_callback=self._translate_event,
        )

    async def switch_model(self, model: str, effort: str) -> None:
        """Apply an already validated selection between worker turns."""
        await self.client.cancel()
        self.spec.model = model
        self.spec.effort = effort
        self.session_id = ""
        self.spec.session_uuid = ""
        self.client = self._new_client()
        self._started = False

    async def start(self) -> None:
        if self._started:
            return
        self.spec.cwd.mkdir(parents=True, exist_ok=True)
        self._started = True
        self._emit({
            "type": "system",
            "subtype": "init",
            "cwd": str(self.spec.cwd),
            "session_id": self.session_id,
            "tools": ["bash", "read", "write", "edit", "grypton MCP"],
            "mcp_servers": [{"name": "grypton", "status": "configured"}],
            "model": self.spec.model,
            "permissionMode": "auto",
        })

    async def ensure_started(self) -> None:
        if not self._started:
            await self.start()

    async def rewind_idle_tail(self) -> int:
        """Drop an idle/refusal conversation while preserving workspace state."""
        self.session_id = ""
        self.spec.session_uuid = ""
        return 0

    async def aclose(self) -> None:
        await self.client.cancel()
        self._started = False

    def _build_prompt(self, directive: str) -> str:
        tool_bin = config.find_binary("grypton-tool") or str(config.BIN_DIR / "grypton-tool")
        slug = self.spec.extra_env.get("GRYPTON_TARGET", self.spec.cwd.name)
        return (
            "=== GRYPTON KRAUDE WORKER RUNTIME ===\n"
              "Native Bash/read/write/edit tools and `grypton_*` MCP tools are "
              "available. Every network action MUST use a `grypton_*` MCP tool so "
              "scope checks and Burp-like request/response capture cannot be bypassed. "
              "Native Bash is only for local analysis; do not use curl, wget, httpx, "
              "language HTTP libraries, sockets, or built-in web fetch/search for "
              "network access. Prefer ledger tools for durable findings, surface "
              "entries, and tested techniques. Before every network action call "
              "`grypton_read_doc` with `{\"name\": \"scope\"}`. Use `grypton_read_doc` "
              "for scope, program, findings, surface, tested, and progress ledgers; do not "
              "use native Read on absolute engagement paths. Do not inspect files outside "
              "this engagement workspace.\n"
            + f"If an MCP tool is unavailable, use the scoped CLI fallback with global options first: "
              f"`{tool_bin} --json --target {slug} read scope`. The fallback tool, never curl "
              "or a language HTTP client, is the only permitted network fallback.\n\n"
              "=== KRYPTEX DIRECTIVE ===\n"
            + directive
        )

    async def run_turn(self, text: str) -> TurnResult:
        await self.ensure_started()
        started = time.time()
        try:
            result = await self.client.call(
                self._build_prompt(text),
                session_id=self.session_id,
                timeout=self.spec.turn_timeout_s,
                title=f"Grypton Kraude {self.spec.cwd.name}",
            )
        except ProviderError as exc:
            raise WorkerError(str(exc)) from exc
        self.session_id = result.session_id
        self.spec.session_uuid = result.session_id
        tools = [{
            "name": self._tool_name(item.get("name")),
            "input": item.get("input") if isinstance(item.get("input"), dict) else {},
            "output": item.get("output", ""),
            "is_error": bool(item.get("is_error")),
            "id": item.get("id"),
        } for item in result.tools]
        return TurnResult(
            assistant_text=result.text,
            tool_uses=tools,
            result={
                "session_id": result.session_id,
                "usage": result.usage,
                "event_count": len(result.events),
                "returncode": result.returncode,
            },
            num_turns=1,
            duration_s=time.time() - started,
            cost_usd=result.cost,
        )

    @staticmethod
    def _tool_name(name) -> str:
        raw = str(name or "tool")
        return {
            "bash": "Bash", "read": "Read", "write": "Write", "edit": "Edit",
            "webfetch": "WebFetch", "websearch": "WebSearch", "grep": "Grep",
            "glob": "Glob", "list": "List",
        }.get(raw, raw)

    def _emit(self, event: dict) -> None:
        if self.on_event:
            try:
                self.on_event(event)
            except Exception:
                pass

    def _translate_event(self, event: dict) -> None:
        event_type = event.get("type")
        part = event.get("part") if isinstance(event.get("part"), dict) else {}
        if event_type == "text" and isinstance(part.get("text"), str):
            self._emit({
                "type": "stream_event",
                "event": {"type": "content_block_delta",
                          "delta": {"type": "text_delta", "text": part["text"]}},
            })
            return
        if event_type in {"reasoning", "thinking"} and isinstance(part.get("text"), str):
            self._emit({
                "type": "stream_event",
                "event": {"type": "content_block_delta",
                          "delta": {"type": "thinking_delta", "thinking": part["text"]}},
            })
            return
        if event_type != "tool_use":
            return
        state = part.get("state") if isinstance(part.get("state"), dict) else {}
        metadata = state.get("metadata") if isinstance(state.get("metadata"), dict) else {}
        tool_id = part.get("callID") or part.get("id") or "tool"
        name = self._tool_name(part.get("tool"))
        inputs = state.get("input") if isinstance(state.get("input"), dict) else {}
        failed = str(state.get("status", "")) in {"error", "failed"} or bool(metadata.get("exit"))
        self._emit({
            "type": "assistant",
            "message": {"role": "assistant", "content": [{
                "type": "tool_use", "id": tool_id, "name": name, "input": inputs,
            }]},
        })
        self._emit({
            "type": "user",
            "message": {"role": "user", "content": [{
                "type": "tool_result", "tool_use_id": tool_id,
                "content": tool_state_text(state), "is_error": failed,
            }]},
        })


# Compatibility name used by restored engine imports.
KraudeWorker = OpenCodeWorker
