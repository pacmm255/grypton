"""Kraude: a persistent, selectable worker driven through OpenCode/OpenClaude."""
from __future__ import annotations

from dataclasses import dataclass, field
import math
from pathlib import Path
import time
from typing import Callable, Optional

from . import config
from .providers import OpenCodeClient, ProviderError, tool_state_text


EventCb = Optional[Callable[[dict], None]]


def _token_count(value) -> Optional[int]:
    """Return one trustworthy non-negative token count."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()):
        return None
    count = int(value)
    return count if count >= 0 else None


def _opencode_step_context_tokens(value) -> Optional[int]:
    """Return the live footprint from one canonical OpenCode token record.

    A valid provider total is its best prospective next-call estimate. Without
    one, OpenCode's fields are non-overlapping: uncached input, cache reads and
    writes, visible output, and reasoning. Their sum estimates the conversation
    that will be carried into the next model step.
    """
    if not isinstance(value, dict):
        return None
    explicit_total = _token_count(value.get("total"))
    if explicit_total is not None:
        return explicit_total

    input_tokens = _token_count(value.get("input"))
    output_tokens = _token_count(value.get("output"))
    reasoning_tokens = _token_count(value.get("reasoning"))
    cache = value.get("cache")
    if (
        input_tokens is None
        or output_tokens is None
        or reasoning_tokens is None
        or not isinstance(cache, dict)
    ):
        return None
    cache_read = _token_count(cache.get("read"))
    cache_write = _token_count(cache.get("write"))
    if cache_read is None or cache_write is None:
        return None
    return (
        input_tokens + output_tokens + reasoning_tokens
        + cache_read + cache_write
    )


def usage_context_tokens(usage) -> Optional[int]:
    """Return the latest valid OpenCode step's live context footprint.

    Every later agentic step, and every resumed provider call, sends the prior
    conversation again. Summing those records counts the same context many
    times. Walk backward to the final valid step and ignore older observations.
    """
    if not isinstance(usage, list) or not usage:
        return None
    for step in reversed(usage):
        footprint = _opencode_step_context_tokens(step)
        if footprint is not None:
            return footprint
    return None


class WorkerError(RuntimeError):
    """Worker failure retaining sanitized provider classification metadata."""

    def __init__(self, message: str, *, metadata: Optional[dict] = None):
        super().__init__(message)
        self.metadata = dict(metadata or {})


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
        self._pool_exhaustion_reset_used = False
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
            agent_prompt=self.spec.system_prompt,
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
        self._pool_exhaustion_reset_used = False

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
            "tools": [
                "read", "grep", "glob", "bash", "edit", "task",
                "grypton MCP (scoped network + evidence tools)",
            ],
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

    def rollover_session(self) -> None:
        """Forget only Kraude's conversation after durable engine persistence."""
        self.session_id = ""
        self.spec.session_uuid = ""
        self._pool_exhaustion_reset_used = False

    async def aclose(self) -> None:
        await self.client.cancel()
        self._started = False

    def _build_prompt(self, directive: str) -> str:
        # Role, engagement data, and tool schemas are already installed in the
        # agent configuration. Keep the live instruction exactly as supplied by
        # the operator or Kryptex so generated conduct rules cannot distort it.
        return directive

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
            metadata = exc.metadata
            if (
                not self._pool_exhaustion_reset_used
                and metadata.get("source") == "openclaude"
                and metadata.get("type") == "openclaude_terminal"
                and metadata.get("role") == "worker"
                and metadata.get("reason") == "credential_pool_exhausted"
                and metadata.get("upstream_status") == 429
            ):
                # OpenCode sessions can retain provider-specific conversation
                # state across calls. Consume one fresh-session recovery for a
                # consecutive 429 exhaustion burst. The engine retries from
                # durable workspace state and suppresses exact replay whenever
                # the native-capable provider process may have executed work.
                self.session_id = ""
                self.spec.session_uuid = ""
                self._pool_exhaustion_reset_used = True
            raise WorkerError(str(exc), metadata=metadata) from exc
        self._pool_exhaustion_reset_used = False
        self.session_id = result.session_id
        self.spec.session_uuid = result.session_id
        context_tokens = usage_context_tokens(result.usage)
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
                **({
                    "context_tokens": context_tokens,
                } if context_tokens is not None else {}),
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
