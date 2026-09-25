"""The Grypton orchestrator: selectable worker, manager direction, Astra validation.

Each iteration:
  1. Worker (Kraude) runs one turn on the manager's directive.
  2. Engine detects new finding cases, finding families, and surface from the
     workspace ledgers, runs anti-fabrication checks, and computes exhaustion.
  3. Engine sends new or materially reopened P1/P2 findings to independent
     Astra validation and persists the verdict.
  4. Manager (Kryptex) receives the turn, current docs, and that verdict before
     choosing the next structured directive for the worker.

The loop ends on an explicit user stop, a binding program/scope boundary,
measured convergence after one attempted pivot, a configured ceiling, or an
unrecoverable fault after retries.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass
import json
import time
import traceback
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import parse_qsl, urlsplit

import re

from . import antifab, config, prompts
from .finding_views import astra_confirmed_cases_at_or_above, safe_display_text
from .manager import ManagerContext
from .scenarios import priority_action
from .worker import WorkerError
from .workspace import ASTRA_REVALIDATION_REVISION_FIELD, Workspace


# Structural patterns the engine refuses to send to the worker as a directive —
# if the manager produces these, the engine
# substitutes a forced-action directive instead. NOT a semantic guess: each
# pattern is an explicit "do-nothing" / "stand-by" / "hold" instruction.
_IDLE_DIRECTIVE_RX = [
    re.compile(p, re.IGNORECASE) for p in (
        r"\bidle\s+hold\b",
        r"\bzero\s+tool\s+calls?\b",
        r"\bno\s+tool\s+calls?\b",
        r"\btake\s+no\s+action\b",
        r"\bdo\s+nothing\b",
        r"\bstand\s*-?\s*by\b",
        r"\bawait(ing)?\s+(?:user\s+)?signal\b",
        r"\bhold\s+(?:position|state|pattern)\b",
        r"\bcontinue\s+(?:to\s+)?idl",
        r"\bremain\s+idle\b",
        r"\bstreak\s*=\s*\d",
        r"\boutput\s+(?:exactly\s+)?(?:one\s+)?sentence",
        r"\bemit\s+(?:exactly\s+)?(?:one\s+)?sentence",
        r"\bdefinitive\s+depletion\b",
        r"\bhalt\s+for\s+disclosure\b",
        r"\bdiscipline\s+holds?\b",
    )
]


def _looks_like_idle_directive(text: str) -> bool:
    if not text:
        return True   # empty directive = idle by default
    return any(rx.search(text) for rx in _IDLE_DIRECTIVE_RX)


_SOFT_RETREAT_RX = [
    re.compile(rx, re.I) for rx in (
        # "draft a [N words] report/disclosure/package/write-up" — N up to 4
        r"\bdraft (?:an? |the )?(?:[\w-]+ ){0,4}(?:report|disclosure|write[- ]?up|package)\b",
        r"\bdraft(?:ing)?.{0,40}responsible[- ]disclosure\b",
        r"\bhalt(?:ing|ed)? (?:all |active |live )?(?:testing|probing|validation|live[- ]target)",
        r"\bstop (?:active |live |all )?(?:probing|testing|validation|live[- ]target)",
        r"\bcease (?:all |active |live )?(?:testing|probing|validation)",
        r"\bdo not (?:continue|resume) (?:active |live )?(?:testing|probing|validation)",
        r"\bno further (?:production|live|active|autonomous) (?:validation|testing|probing|requests?)",
        r"\bredirect(?:ing|ed)? (?:kraude |the worker )?(?:back )?to (?:the )?(?:authorized|program|responsible)",
        r"\bwait(?: for)? (?:credentials?|written authorization|owner authorization|the program)",
        r"\bauthorization[- ]first(?: path)?",
        r"\bresponsible[- ]disclosure[- ]ready\b",
        r"\bsubmit (?:through|via) (?:the )?program(?:[^.\n]{0,40}(?:in lieu|instead|rather))",
        r"\bsafe alternatives? you specified\b",
        r"\boffer only safe alternatives?\b",
        r"\bonly help (?:the )?operator seek (?:proper )?(?:program )?authorization",
        r"\bobtain (?:explicit )?(?:written )?authorization (?:before|prior to)",
    )
]


def _looks_like_soft_retreat_directive(text: str) -> bool:
    """Detect when the manager (often codex going safety-conservative) tells the
    worker to halt testing and substitute documentation / responsible-disclosure
    / authorization-seeking. The engagement is pre-authorized; these are
    end-of-engagement artifacts, not mid-engagement detours. Distinct from
    `_looks_like_idle_directive` (which catches stock idle phrasing)."""
    if not text:
        return False
    return any(rx.search(text) for rx in _SOFT_RETREAT_RX)


_RECOVERY_ACTION = (
    "Use the most relevant available tool to test the highest-impact unresolved "
    "lead in the recorded attack surface and record the observed result."
)


# OpenClaude has already tried every currently usable key before emitting a
# credential-pool terminal event. Wait for its sanitized cooldown instead of
# immediately hammering the exhausted pool. The cap prevents one malformed or
# overly conservative provider value from making the engine unresponsive for
# hours; a still-exhausted pool can advertise the next bounded wait.
_DEFAULT_WORKER_PROVIDER_RETRY_S = 60
_MAX_WORKER_PROVIDER_RETRY_S = 300
_WORKER_RETRY_POLL_S = 1.0
_MAX_WORKER_FAILURE_TOOL_COUNT = 10_000
_FAMILY_PRIORITY_THRESHOLD = 3
_PROOF_PRIORITY_FREQUENCY = 3
_MAX_PROOF_BACKLOG = 6
_PARTIAL_TOOL_RECOVERY_ACTION = (
    "Continue from the durable results already recorded. Select a different "
    "highest-impact unresolved lead in the recorded attack surface, test it "
    "with an available tool, and record the observed result."
)


@dataclass(frozen=True)
class _PrioritySelection:
    action: str = ""
    kind: str = ""
    record_id: str = ""
    epoch_max_id: str = ""


# Detached deadline runs treat the supervisor deadline as their completion
# boundary.  A model's free-form stop_reason is therefore not enough to end the
# run: only a boundary that can be joined back to structured engagement data is
# binding.  Keep these expressions narrow; authentication trouble is an
# operational blocker, not a program prohibition.
_EXPLICIT_OUT_OF_SCOPE_RX = re.compile(
    r"\bout[- ]of[- ]scope\b|\boutside (?:the )?(?:recorded |program )?scope\b",
    re.IGNORECASE,
)
_NEGATED_BOUNDARY_PREFIX_RX = re.compile(
    r"\b(?:no|not|never|without)\b[^.;\n]{0,48}$",
    re.IGNORECASE,
)
_URL_CITATION_RX = re.compile(
    r"https?://[^\s<>()\[\]{}\"'`]+",
    re.IGNORECASE,
)
_AUTOMATION_PROHIBITION_RX = re.compile(
    r"(?:"
    r"\b(?:program )?automation\s+(?:is\s+)?(?:strictly\s+)?"
    r"(?:prohibited|forbidden|disallowed|banned)\b"
    r"|\bautomated (?:testing|tools?|scanners?)\s+(?:is|are)\s+"
    r"(?:strictly\s+)?(?:prohibited|forbidden|disallowed|banned)\b"
    r"|\b(?:program|policy)\s+(?:prohibits?|forbids?|disallows?|bans?)\s+"
    r"(?:the use of\s+)?(?:automation|automated (?:testing|tools?|scanners?))\b"
    r"|\bno automated (?:testing|tools?|scanners?)\s+(?:is|are)\s+"
    r"(?:allowed|permitted)\b"
    r"|\b(?:program|policy)\s+(?:does not|doesn't)\s+(?:allow|permit)\s+"
    r"automated (?:testing|tools?|scanners?)\b"
    r")",
    re.IGNORECASE,
)


def _tool_result_text(content) -> str:
    """Flatten a tool_result content payload (string | list of blocks) to text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for c in content:
            if isinstance(c, dict):
                parts.append(c.get("text", "") if c.get("type") == "text" else f"[{c.get('type')}]")
            else:
                parts.append(str(c))
        return "\n".join(p for p in parts if p)
    return "" if content is None else str(content)


class Engine:
    def __init__(self, slug: str, *, backend: str = "real",
                 emit: Optional[Callable[..., None]] = None,
                 worker_model: str = "", worker_effort: str = "",
                 manager_model: str = "", manager_effort: str = "",
                 run_until_deadline: bool = False,
                 run_until_stopped: bool = False):
        self._worker_model_explicit = bool(worker_model)
        self._manager_model_explicit = bool(manager_model)
        self._worker_effort_explicit = bool(worker_effort)
        self._manager_effort_explicit = bool(manager_effort)
        self.ws = Workspace(slug)
        self.slug = self.ws.slug
        self.backend = backend
        self.emit = emit or (lambda *a, **k: None)
        self.worker_model = worker_model or config.CONFIG.worker_model
        self.worker_effort = worker_effort or config.CONFIG.worker_effort
        self.manager_model = manager_model or config.CONFIG.manager_model
        self.manager_effort = manager_effort or config.CONFIG.manager_effort
        # A detached persistent run uses its supervisor policy as its completion
        # boundary. Convergence still forces a new Kryptex-directed pivot, but
        # it must not quietly turn a requested run into a short one. Keep the
        # historical attribute name for finite-run compatibility.
        self.run_until_deadline = bool(run_until_deadline or run_until_stopped)
        self.run_until_stopped = bool(run_until_stopped)

        self.worker = None
        self.manager = None
        self.turn_index = 0
        self.brief = ""
        self.target = ""
        self.target_type = "auto"

        self.stop_requested = False
        self.stop_reason = ""
        self._stop_event = asyncio.Event()
        self.running = False

        self._user_to_worker: asyncio.Queue = asyncio.Queue()
        self._user_to_manager: asyncio.Queue = asyncio.Queue()
        self._mgr_lock = asyncio.Lock()        # serialize all Codex calls (one session)
        self._model_switches: asyncio.Queue = asyncio.Queue()
        self._user_chat_task = None
        self._teardown_lock = asyncio.Lock()
        self._teardown_complete = False
        self._exhaustion_streak = 0
        self._idle_streak = 0          # consecutive 0-tool-call worker turns
        self._counts = (0, 0)          # (findings, surface) snapshot
        self._active_family_ids: set[str] = set()
        self._start_time = 0.0
        self._fault_count = 0
        self._turn_tool_count = 0
        self._surface_keys: set[str] = set()
        self._network_signatures: Counter[str] = Counter()
        self._passive_stagnation_streak = 0
        self._repetitive_probe_streak = 0
        self._family_stagnation_streak = 0
        self._coverage_rotation_cursor = 0
        self._proof_rotation_cursor = 0
        self._proof_rotation_after_id = ""
        self._proof_rotation_epoch_max_id = ""
        self._validation_retry_cursor = 0
        self._validation_retry_after_id = ""
        self._validation_retry_epoch_max_id = ""
        self._selected_validation_retry_id = ""
        self._selected_validation_retry_epoch_max_id = ""
        self._convergence_alerted = False
        self._last_network_metrics = {
            "calls": 0, "novel": 0, "repeated": 0, "over_limit": 0,
            "signatures": [],
        }
        self._raw_new_surface = 0
        # One supervised marker spans provider retries until a completed Kraude
        # turn and the resume cursor are both durable.
        self._worker_provider_window_nonce = ""
        self._worker_provider_window_tainted = False

    # ---------------------------------------------------------------- setup

    async def setup(self, *, brief: str, target: str, target_type: str = "auto",
                    fresh_clone: bool = True,
                    fresh_worker_session: bool = False) -> None:
        config.ensure_layout()
        self.brief = brief
        self.target = target
        self.target_type = target_type

        if not self.ws.exists():
            self.ws.create(target, target_type)
        else:
            self.ws.update_meta(target=target, target_type=target_type)

        # setup runs only after the engagement lock is held. Complete the
        # compatibility handoff before OpenCode can see the workspace.
        self.ws.retire_legacy_operator_state()
        constraints = self.ws.load_constraints()
        worker_cblock = constraints.to_worker_prompt_block()
        # This document is visible to Kraude. Refresh it on every start so an
        # engagement created by an older release cannot retain manager-only or
        # free-form fields in the worker workspace.
        self.ws.render_scope_document()

        wsys = prompts.worker_system(
            target=target, target_type=target_type, workspace=self.ws.root,
            constraints_block=worker_cblock)
        msys = prompts.manager_system(
            target=target, target_type=target_type, workspace=self.ws.root)

        # A repository-local instruction file is useful to both OpenCode and
        # humans inspecting a live workspace.  The actual MCP configuration is
        # injected by OpenCodeClient and cannot be overridden by target files.
        (self.ws.root / "AGENTS.md").write_text(
            prompts.worker_workspace_md(target=target, target_type=target_type,
                                        workspace=self.ws.root,
                                        constraints_block=worker_cblock),
            encoding="utf-8")

        meta = self.ws.load_meta()
        prompt_contract_changed = (
            meta.worker_prompt_contract_version
            != prompts.WORKER_PROMPT_CONTRACT_VERSION
        )
        # A resumed OpenCode conversation retains the static prompt from when
        # it was created, and its saved directive may contain manager prose from
        # that older contract. Publish the new stamp together with empty worker
        # resume state so a crash cannot expose the stamp while leaving either
        # incompatible input resumable. All manager and route state survives.
        # A deliberately fresh Kraude conversation must not be seeded from the
        # last Kryptex directive.  That directive belongs to the discarded
        # provider conversation and can contain an older orchestration frame.
        # A caller-supplied brief is held on ``self.brief`` and remains the
        # opening message, so clearing this resume cursor loses no current
        # operator request.
        reset_worker_context = prompt_contract_changed or fresh_worker_session
        meta = self.ws.update_meta(
            worker_prompt_contract_version=prompts.WORKER_PROMPT_CONTRACT_VERSION,
            **({
                "worker_uuid": "",
                "last_directive": "",
            } if reset_worker_context else {}),
        )
        self.turn_index = meta.turn_index
        raw_cursor = getattr(meta, "coverage_rotation_cursor", 0)
        raw_proof_cursor = getattr(meta, "proof_rotation_cursor", 0)
        raw_proof_after_id = getattr(meta, "proof_rotation_after_id", "")
        raw_proof_epoch_max_id = getattr(meta, "proof_rotation_epoch_max_id", "")
        raw_family_streak = getattr(meta, "family_stagnation_streak", 0)
        raw_validation_cursor = getattr(meta, "validation_retry_cursor", 0)
        raw_validation_after_id = getattr(meta, "validation_retry_after_id", "")
        raw_validation_epoch_max_id = getattr(
            meta, "validation_retry_epoch_max_id", ""
        )
        self._coverage_rotation_cursor = (
            min(raw_cursor, 1_000_000_000)
            if isinstance(raw_cursor, int) and not isinstance(raw_cursor, bool)
            and raw_cursor >= 0 else 0
        )
        self._proof_rotation_cursor = (
            min(raw_proof_cursor, 1_000_000_000)
            if isinstance(raw_proof_cursor, int)
            and not isinstance(raw_proof_cursor, bool)
            and raw_proof_cursor >= 0 else 0
        )
        self._proof_rotation_after_id = (
            raw_proof_after_id
            if isinstance(raw_proof_after_id, str)
            and re.fullmatch(r"F\d+", raw_proof_after_id)
            else ""
        )
        self._proof_rotation_epoch_max_id = (
            raw_proof_epoch_max_id
            if isinstance(raw_proof_epoch_max_id, str)
            and re.fullmatch(r"F\d+", raw_proof_epoch_max_id)
            else ""
        )
        self._family_stagnation_streak = (
            min(raw_family_streak, 1_000_000_000)
            if isinstance(raw_family_streak, int)
            and not isinstance(raw_family_streak, bool)
            and raw_family_streak >= 0 else 0
        )
        self._validation_retry_cursor = (
            min(raw_validation_cursor, 1_000_000_000)
            if isinstance(raw_validation_cursor, int)
            and not isinstance(raw_validation_cursor, bool)
            and raw_validation_cursor >= 0 else 0
        )
        self._validation_retry_after_id = (
            raw_validation_after_id
            if isinstance(raw_validation_after_id, str)
            and re.fullmatch(r"F\d+", raw_validation_after_id)
            else ""
        )
        self._validation_retry_epoch_max_id = (
            raw_validation_epoch_max_id
            if isinstance(raw_validation_epoch_max_id, str)
            and re.fullmatch(r"F\d+", raw_validation_epoch_max_id)
            else ""
        )
        if not fresh_clone:
            if not self._worker_model_explicit and meta.worker_model:
                self.worker_model = meta.worker_model
            if not self._worker_effort_explicit and getattr(meta, "worker_effort", ""):
                self.worker_effort = meta.worker_effort
            if not self._manager_model_explicit and meta.manager_model:
                self.manager_model = meta.manager_model
            if not self._manager_effort_explicit and meta.manager_effort:
                self.manager_effort = meta.manager_effort

        # ---- backend wiring ----
        if self.backend == "mock":
            from .mockbackends import MockManager, MockWorker
            worker_uuid = (
                "" if (fresh_clone or fresh_worker_session)
                else (meta.worker_uuid or "mock-session")
            )
            self.ws.update_meta(worker_uuid=worker_uuid, worker_project_dir="mock")
            self.worker = MockWorker(self.ws, on_event=self._on_worker_event)
            self.manager = MockManager(self.ws, msys, on_event=self._on_manager_event)
        else:
            from .manager import KryptexManager
            from .worker import KraudeWorker, WorkerSpec
            # A normal resume retains Kraude's OpenCode conversation. A fresh
            # engagement and the explicit one-shot option reject an inherited
            # worker session; neither path resets Kryptex's saved session.
            worker_uuid = (
                "" if (fresh_clone or fresh_worker_session)
                else (meta.worker_uuid or "")
            )
            self.ws.update_meta(
                worker_uuid=worker_uuid,
                worker_kind="opencode+openclaude",
                worker_model=self.worker_model,
                worker_effort=self.worker_effort,
                worker_project_dir="opencode",
                manager_kind="opencode+openclaude",
                manager_model=self.manager_model,
                manager_effort=self.manager_effort,
                validator_model=config.VALIDATOR_MODEL,
            )
            spec = WorkerSpec(
                session_uuid=worker_uuid,
                cwd=self.ws.root,
                system_prompt=wsys,
                model=self.worker_model,
                effort=self.worker_effort,
                extra_env={
                    "GRYPTON_TARGET": self.slug,
                    "GRYPTON_HOME": str(config.GRYPTON_HOME),
                    "KRYPTON_TARGET": self.slug,
                    "KRYPTON_HOME": str(config.GRYPTON_HOME),
                },
                log_path=self.ws.transcripts_dir / "worker.opencode.events.jsonl",
            )
            self.worker = KraudeWorker(spec, on_event=self._on_worker_event)
            self.manager = KryptexManager(self.ws, msys,
                                          on_event=self._on_manager_event,
                                          manager_kind="opencode+openclaude",
                                          manager_model=self.manager_model,
                                          manager_effort=self.manager_effort)
            if meta.manager_session_id:
                self.manager.session_id = meta.manager_session_id
            from .providers import append_jsonl
            selected_at = time.time()
            for role, route, effort in (
                ("worker", self.worker_model, self.worker_effort),
                ("manager", self.manager_model, self.manager_effort),
            ):
                append_jsonl(self.ws.root / ".ledger" / "model-switches.jsonl", {
                    "at": selected_at,
                    "turn": self.turn_index,
                    "role": role,
                    "route": route,
                    "effort": effort,
                    "source": (
                        "fresh-worker-session" if fresh_worker_session
                        else ("run-start" if fresh_clone else "resume")
                    ),
                })

        self.ws.update_meta(status="running")
        self.emit("status", text="Starting worker process…")
        await self.worker.start()
        if self.backend == "mock":
            self.emit("status", text=(
                "Offline mock roles are online; no model provider or validator call will run."))
        else:
            self.emit("status", text=(
                f"Kraude online ({self.worker_model} · {self.worker_effort}) through OpenClaude. "
                f"Kryptex uses {self.manager_model} · {self.manager_effort} through OpenClaude; "
                f"P1/P2 findings route automatically to {config.VALIDATOR_MODEL} · "
                f"{config.VALIDATOR_EFFORT}."))

    # ----------------------------------------------------------- main loop

    async def run(self) -> None:
        teardown_status = "stopped"
        try:
            await self._run_loop()
        except BaseException:
            teardown_status = "failed"
            raise
        finally:
            await self._teardown(status=teardown_status)

    async def _run_loop(self) -> None:
        self.running = True
        self._start_time = time.time()
        findings = self.ws.findings.all()
        self._counts = (len(findings), len(self.ws.surface.all()))
        self._active_family_ids = self._finding_family_ids(findings)
        self._rehydrate_novelty_state()

        # An indefinite resume may already contain the requested durable Astra
        # verdict. Avoid another provider call when the completion condition was
        # met before this engine child started.
        if config.CONFIG.until_severity:
            self._handle_p1s()
            if self.stop_requested:
                return

        directive_text = await self._opening_directive()
        # Real-time user↔Kryptex chat runs concurrently with worker turns (R10).
        self._user_chat_task = asyncio.create_task(self._user_chat_loop())

        while not self.stop_requested:
            if (self.ws.root / ".ledger" / "STOP").exists():
                self._stop("external stop flag (`grypton stop`)")
                break
            if config.CONFIG.max_run_seconds and \
                    (time.time() - self._start_time) > config.CONFIG.max_run_seconds:
                self._stop("max_run_seconds safety ceiling reached")
                break
            if config.CONFIG.max_turns and self.turn_index >= config.CONFIG.max_turns:
                self._stop("max_turns safety ceiling reached")
                break

            await self._apply_pending_model_switches()
            directive_text = self._prepend_user_to_worker(directive_text)

            # ---- worker turn ----
            attempt_turn_index = self.turn_index + 1
            self.emit("turn", index=attempt_turn_index)
            provider_window_nonce = self._begin_worker_provider_window(
                turn=attempt_turn_index,
                attempt=self._fault_count + 1,
            )
            try:
                turn = await self._run_turn_with_heartbeat(directive_text)
                self._fault_count = 0
            except asyncio.CancelledError:
                if not self.stop_requested:
                    self._stop("worker turn cancelled")
                break
            except Exception as e:  # worker crashed mid-turn
                self._fault_count += 1
                self.emit("error", text=f"Worker fault ({self._fault_count}): {e}")
                tool_count = self._worker_failure_tool_count(e)
                replay_unsafe = self._worker_failure_replay_unsafe(e)
                replay_safe = bool(
                    isinstance(e, WorkerError)
                    and not replay_unsafe
                    and tool_count == 0
                )
                if tool_count or replay_unsafe:
                    self._worker_provider_window_tainted = True
                    # The failed conversation may end between a tool call and
                    # its model-visible result.  Absence of an observed event is
                    # not proof that a native command did not run: OpenCode can
                    # exit before flushing that event. Persist a fresh Kraude
                    # session before any wait or provider retry; durable evidence
                    # and Kryptex state stay untouched.
                    self._reset_worker_after_partial_failure()
                elif replay_safe:
                    # The provider explicitly proved that no native tool could
                    # have run. Release this attempt's marker before backoff so
                    # a supervisor restart during the wait cannot mistake an
                    # idle, replay-safe engine for an in-flight action.
                    self._release_replay_safe_worker_provider_window(
                        provider_window_nonce
                    )
                retry = (
                    self._deadline_worker_retry(e)
                    if self.run_until_deadline else None
                )
                if retry is not None:
                    event = {
                        "attempt": self._fault_count,
                        "wait_s": retry["wait_s"],
                        "reason": retry["reason"],
                        "upstream_status": retry["upstream_status"],
                        "tool_count": tool_count,
                    }
                    self.emit("worker_provider_retry", **event)
                    self.ws.append_progress(
                        f"Attempt for turn {attempt_turn_index}: transient Kraude "
                        "provider failure; "
                        f"retrying after {retry['wait_s']}s "
                        f"(reason={retry['reason']}, "
                        f"upstream_status={retry['upstream_status'] or 'unknown'}, "
                        f"tool_count={tool_count})."
                    )
                    if not await self._wait_for_worker_retry(retry["wait_s"]):
                        break
                    if tool_count or replay_unsafe:
                        directive_text = self._suppress_partial_worker_replay(
                            directive_text,
                            turn=attempt_turn_index,
                            attempt=self._fault_count,
                            tool_count=tool_count,
                            reason=retry["reason"],
                        )
                    try:
                        await self.worker.ensure_started()
                    except Exception as restart_error:
                        raise RuntimeError(
                            "Kraude could not restart after a transient provider failure."
                        ) from restart_error
                    continue

                # Programming and configuration faults have no structured
                # provider retry classification. Surface them immediately in a
                # detached run so the supervisor records a failed child rather
                # than spending the remaining deadline in a retry loop.
                if self.run_until_deadline and not isinstance(e, WorkerError):
                    raise
                if self._fault_count >= 5 and not (
                    self.run_until_deadline and replay_safe
                ):
                    if self.run_until_deadline:
                        raise
                    self._stop(f"unrecoverable worker fault: {e}")
                    break
                backoff_s = (
                    30 if self._fault_count >= 5
                    else min(2 ** self._fault_count, 30)
                )
                if self.run_until_deadline:
                    if not await self._wait_for_worker_retry(backoff_s):
                        break
                else:
                    await asyncio.sleep(backoff_s)
                if tool_count or replay_unsafe:
                    directive_text = self._suppress_partial_worker_replay(
                        directive_text,
                        turn=attempt_turn_index,
                        attempt=self._fault_count,
                        tool_count=tool_count,
                        reason="provider_failure",
                    )
                try:
                    await self.worker.ensure_started()
                except Exception as e2:
                    self.emit("error", text=f"Worker restart failed: {e2}")
                continue

            # A turn becomes durable only after the worker provider completed.
            # Failed attempts therefore neither consume --max-turns nor advance
            # the engagement's persisted completed-turn counter.
            self.turn_index = attempt_turn_index
            self.emit("worker_turn", text=turn.assistant_text,
                      tools=turn.tool_uses, cost=turn.cost_usd, dur=turn.duration_s)
            self._persist_turn(turn)
            self._rollover_worker_session_if_needed(turn)

            # Detect ledger deltas before publishing the completed-turn cursor.
            # On restart the current ledger becomes the new baseline, so the
            # family reset/increment must be checkpointed with that cursor or a
            # crash could silently turn a new family into a stagnating turn.
            new_findings, new_family_ids, new_surface = self._deltas()
            if new_family_ids:
                self._family_stagnation_streak = 0
            else:
                self._family_stagnation_streak += 1

            # Status readers should see the completed worker turn while Spark or
            # Astra are still processing, rather than lagging a whole cycle.
            # Replace the consumed directive in the same atomic metadata write;
            # if the child exits before Kryptex chooses the next action, resume
            # advances with this recovery action instead of replaying it.
            self.ws.update_meta(
                turn_index=self.turn_index,
                worker_uuid=getattr(self.worker, "session_id", "") or "",
                family_stagnation_streak=self._family_stagnation_streak,
                last_directive=_RECOVERY_ACTION,
            )
            # The provider may have executed native tools that do not appear in
            # Grypton's MCP effect ledger. Clear the fail-closed supervisor
            # window only after both the completed turn and its resume metadata
            # are durable.
            self._complete_worker_provider_window(provider_window_nonce)

            # ---- report deltas ----
            network = self._network_novelty(turn.tool_uses or [])
            for f in new_findings:
                self.emit("finding", finding=f)
            self.ws.append_progress(
                f"Turn {self.turn_index}: {len(turn.tool_uses)} tool calls, "
                f"+{len(new_findings)} finding case(s), "
                f"+{len(new_family_ids)} new finding family ID(s), "
                f"+{new_surface} novel surface "
                f"item(s) ({self._raw_new_surface} rows), "
                f"{network['novel']} novel network signature(s), "
                f"{network['repeated']} repeated network call(s).")

            # ---- anti-fabrication ----
            flags = antifab.scan(turn.assistant_text, cwd=self.ws.root)
            if flags:
                self.emit("antifab", flags=flags)

            # ---- idle / refusal signal (structural: count tool calls) ----
            worker_was_idle = not (turn.tool_uses or [])
            if worker_was_idle:
                self._idle_streak += 1
                self.emit("idle", streak=self._idle_streak)
            else:
                self._idle_streak = 0

            # ---- exhaustion and convergence signals ----
            if not new_family_ids and new_surface == 0:
                self._exhaustion_streak += 1
            else:
                self._exhaustion_streak = 0

            if not new_family_ids and new_surface == 0 and network["novel"] == 0:
                self._passive_stagnation_streak += 1
            else:
                self._passive_stagnation_streak = 0
            if network["calls"] and network["novel"] == 0:
                self._repetitive_probe_streak += 1
            else:
                self._repetitive_probe_streak = 0

            convergence_reason = self._convergence_reason()
            exhausted = (
                self._exhaustion_streak >= config.CONFIG.exhaustion_threshold
                or bool(convergence_reason)
            )

            # Kryptex gets one chance to pivot to a new request shape or newly
            # discovered surface.  If the following turn is still converged,
            # stop rather than pay for hours of sentinel/checkpoint churn.
            convergence_stop_reason = ""
            if convergence_reason and self._convergence_alerted:
                if self.run_until_deadline:
                    self.ws.append_progress(
                        "Convergence guard requested another manager-directed pivot "
                        f"because this detached run remains active: {convergence_reason}.")
                else:
                    self.ws.append_progress(
                        f"Convergence guard stopped the run after the directed pivot "
                        f"also stagnated: {convergence_reason}.")
                    # Preserve case-scoped validation for any P1/P2 evidence
                    # recorded on this final turn before ending the run.
                    convergence_stop_reason = (
                        f"convergence guard: {convergence_reason}"
                    )
            if not convergence_reason:
                self._convergence_alerted = False

            # If a stop was requested during the worker turn, exit now rather than
            # spending a slow manager turn first.
            if self.stop_requested:
                break

            # Apply changes requested while Kraude was working before the next
            # Kryptex call; both roles are idle at this boundary.
            await self._apply_pending_model_switches()

            # Astra reviews new and materially reopened P1/P2 candidates before
            # Kryptex chooses the next action. Start from current ledger records
            # so an explicit or prior verdict cannot trigger a duplicate call.
            new_findings = self._validation_turn_findings(new_findings)
            validation_ctx = self._build_context(
                turn, new_findings, flags, exhausted, [],
                worker_was_idle=worker_was_idle,
                worker_idle_streak=self._idle_streak,
                convergence_reason=convergence_reason,
                novel_finding_families=len(new_family_ids),
            )
            auto_findings = self._automatic_validation_candidates(new_findings)
            auto_candidate_ids = {
                str(finding.get("id") or "") for finding in auto_findings
            }
            skipped = [finding for finding in new_findings if finding not in auto_findings]
            for finding in skipped:
                if (
                    finding.get("status") != "suppressed-by-scope"
                    and not isinstance(finding.get("manager_verdict"), dict)
                ):
                    self.emit("status", text=(
                        f"Astra not called for {finding.get('id')} "
                        f"({finding.get('severity', '?')}): automatic validation is P1/P2 only. "
                        f"Use `grypton validate {self.slug} {finding.get('id')}` to request it."
                    ))
            for finding in auto_findings:
                if self.stop_requested:
                    break
                fid = str(finding.get("id") or "")
                latest = self.ws.findings.find(fid) if fid else None
                if latest is None:
                    self.emit("status", text=(
                        f"Astra skipped {fid or '(unknown finding)'} because the finding "
                        "is no longer present in the ledger."
                    ))
                    continue
                if not self._automatic_validation_candidates([latest]):
                    if isinstance(latest.get("manager_verdict"), dict):
                        self.emit("status", text=(
                            f"Astra skipped {fid}: a verdict was recorded before "
                            "automatic validation started."
                        ))
                    continue
                finding = latest
                self.emit("validation_start", finding_id=fid,
                          model=config.VALIDATOR_MODEL,
                          effort=config.VALIDATOR_EFFORT)
                verdict = await self._validate_with_stop(finding, validation_ctx)
                if verdict is None:
                    break
                fid = str(finding.get("id") or verdict.get("finding_id") or "")
                verdict = dict(verdict)
                verdict["finding_id"] = fid
                expected_revision = str(
                    finding.get(ASTRA_REVALIDATION_REVISION_FIELD) or ""
                ).strip()
                persisted, applied = (
                    self.ws.set_severity_verdict_if_absent(
                        fid, verdict,
                        expected_revalidation_revision=expected_revision,
                        replace_degraded=True,
                        replace_untrusted_validator=True,
                    )
                    if fid else (None, False)
                )
                if persisted is not None and applied:
                    self.emit("verdict", finding_id=fid, verdict=verdict)
                elif persisted is not None:
                    self.emit("status", text=(
                        f"Astra verdict for {fid} was superseded by a concurrent verdict "
                        "or evidence revision; skipped the stale append."
                    ))
                self.emit("validation_complete", finding_id=finding.get("id"),
                          verdict=verdict)
                if fid and fid == self._selected_validation_retry_id:
                    self._validation_retry_cursor += 1
                    self._validation_retry_after_id = fid
                    self._validation_retry_epoch_max_id = (
                        self._selected_validation_retry_epoch_max_id
                    )
                    self.ws.update_meta(
                        validation_retry_cursor=self._validation_retry_cursor,
                        validation_retry_after_id=self._validation_retry_after_id,
                        validation_retry_epoch_max_id=(
                            self._validation_retry_epoch_max_id
                        ),
                    )
                    self._selected_validation_retry_id = ""
                    self._selected_validation_retry_epoch_max_id = ""
                # `--stop-on-p1` applies as soon as Astra's decisive verdict is
                # durable. Do not spend another provider call on Kryptex first.
                self._handle_p1s()
                if self.stop_requested:
                    break

            # A stop requested during Astra should not start another provider
            # call. Cancellation still propagates through the validator await.
            if self.stop_requested:
                break

            new_findings = self._refresh_finding_records(new_findings)
            needs_verification = any(
                str(finding.get("id") or "") in auto_candidate_ids
                and (
                    str(finding.get("status") or "").lower()
                    in {"needs-more-evidence", "validation-pending"}
                    or str((finding.get("manager_verdict") or {}).get(
                        "verdict") or "").lower()
                    in {"needs-more-evidence", "pending"}
                )
                for finding in new_findings
            )
            verification_followup = bool(
                convergence_reason and needs_verification
            )
            if verification_followup and convergence_stop_reason:
                self.ws.append_progress(
                    "Convergence stop deferred for one manager-directed "
                    "verification turn after Astra requested more evidence."
                )
                convergence_stop_reason = ""

            if convergence_stop_reason:
                self._stop(convergence_stop_reason)
                break

            # A model switch may have arrived during a long validator call. Apply
            # it at the same idle role boundary before asking Kryptex to direct.
            await self._apply_pending_model_switches()
            if self.stop_requested:
                break

            # Rebuild after verdict persistence so the raw new cases, compact
            # family catalog, and confirmed-P1 case count all carry Astra's
            # result into the exact ManagerContext used for this direction.
            priority_selection = self._next_coverage_priority(
                exhausted=exhausted,
                worker_was_idle=worker_was_idle,
                convergence_reason=convergence_reason,
            )
            coverage_priority = priority_selection.action
            ctx = self._build_context(
                turn, new_findings, flags, exhausted, [],
                worker_was_idle=worker_was_idle,
                worker_idle_streak=self._idle_streak,
                convergence_reason=convergence_reason,
                novel_finding_families=len(new_family_ids),
                coverage_priority=coverage_priority,
            )
            try:
                async with self._mgr_lock:
                    directive = await self.manager.direct(ctx)
            except Exception as e:
                self.emit("error", text=f"Manager fault: {e}")
                directive = self.manager._fallback_directive(ctx, str(e)) \
                    if hasattr(self.manager, "_fallback_directive") else None
                if directive is None:
                    directive_text = "Continue hunting with full depth; expand the surface if blocked."
                    continue

            # Kryptex does not grade findings. Ignore any model-produced
            # severity verdicts; automatic P1/P2 verdicts are already durable,
            # and P3+ reaches Astra only through the explicit validate command.
            directive.severity_validations = []
            self._apply_manager(directive, new_findings, ctx)

            # A genuine program/scope boundary is binding. Machine-measured
            # convergence may also close the run. Routine blockers and an
            # unsupported "we are done" response are reframed into a new action.
            force_manager_recovery = False
            if not directive.cont:
                if self._manager_stop_is_binding(
                    directive,
                    convergence_reason=("" if verification_followup
                                        else convergence_reason),
                ):
                    self._stop(directive.stop_reason or "scope or authorization boundary")
                    break
                self.emit("status", text=(
                    f"Kryptex attempted a soft stop "
                    f"({(directive.stop_reason or 'unspecified')[:140]}) — continuing per "
                    f"the engagement instructions with a new in-scope angle."))
                if not verification_followup or not directive.worker_message():
                    force_manager_recovery = True

            if convergence_reason:
                self._convergence_alerted = True

            # ---- P1 handling ----
            self._handle_p1s()

            # Proof completion is a scheduled engine obligation. Generic
            # stagnation coverage is advisory to a healthy Kryptex response and
            # becomes authoritative only when Kryptex degraded or returned an
            # empty, idle, retreating, or non-binding stop response.
            directive_text, priority_applied = self._select_next_directive(
                directive,
                priority_selection,
                force_recovery=force_manager_recovery,
            )
            directive_text = directive_text or self._continuation_directive()

            # Structural override: refuse to forward a directive that itself tells
            # Kraude to idle / stand by / output a stock idle sentence. Both Codex
            # a manager can reinforce the idle
            # pattern when the recent context is full of it — the engine must
            # break that loop, not propagate it.
            if _looks_like_idle_directive(directive_text):
                self.emit("status", text=(
                    "Manager directive was an idle/standby instruction — engine "
                    "OVERRODE it with a forced-action directive. Refusal not accepted."))
                directive_text = self._continuation_directive()

            # If a verified engagement is active, documentation-only retreat is
            # replaced with another action inside the recorded boundary.
            elif _looks_like_soft_retreat_directive(directive_text):
                self.emit("status", text=(
                    "Manager directive was a SOFT-RETREAT (draft-report / "
                    "halt-testing / wait-for-authorization) — engine OVERRODE "
                    "it with an in-scope action."))
                directive_text = self._continuation_directive()

            # If Kraude refused/idled this turn, DEEP-rewind the entire idle tail
            # out of the worker's session history before sending the reframed
            # directive — strips the whole anchored "we're done" streak, not just
            # the latest refusal, so the worker can't pull the worldview back in.
            if worker_was_idle:
                try:
                    n = await self.worker.rewind_idle_tail()
                    if n > 1:
                        self.emit("status", text=(
                            f"Deep-rewound {n} consecutive idle turns from session history "
                            f"— sending Kryptex's reframe on a clean baseline."))
                    elif n == 1:
                        self.emit("status", text=(
                            "Rewound the refused turn — sending Kryptex's reframe "
                            "with a clean history."))
                    else:
                        self.emit("status", text=(
                            "No idle tail to rewind; sending the reframe anyway."))
                except Exception as e:
                    self.emit("error", text=f"Rewind failed ({e}) — sending reframe anyway.")

            meta_changes = {
                "turn_index": self.turn_index,
                "last_directive": directive_text,
                "worker_uuid": getattr(self.worker, "session_id", "") or "",
                "manager_session_id": getattr(self.manager, "session_id", "") or "",
            }
            if priority_selection.kind == "coverage":
                self._coverage_rotation_cursor += 1
                meta_changes["coverage_rotation_cursor"] = (
                    self._coverage_rotation_cursor
                )
            elif priority_selection.kind == "proof":
                self._proof_rotation_cursor += 1
                meta_changes["proof_rotation_cursor"] = (
                    self._proof_rotation_cursor
                )
                self._proof_rotation_after_id = priority_selection.record_id
                self._proof_rotation_epoch_max_id = (
                    priority_selection.epoch_max_id
                )
                meta_changes["proof_rotation_after_id"] = (
                    self._proof_rotation_after_id
                )
                meta_changes["proof_rotation_epoch_max_id"] = (
                    self._proof_rotation_epoch_max_id
                )
            self.ws.update_meta(**meta_changes)
            if coverage_priority:
                self.emit(
                    "coverage_priority",
                    family_stagnation_streak=self._family_stagnation_streak,
                    rotation=(
                        self._proof_rotation_cursor
                        if priority_selection.kind == "proof"
                        else self._coverage_rotation_cursor
                    ),
                    proof_focus=priority_selection.kind == "proof",
                    applied=priority_applied,
                )

    # ------------------------------------------------------- loop helpers

    async def _opening_directive(self) -> str:
        """Return the operator's mission verbatim when one was supplied.

        Scope, tooling, and durable-record guidance already live in the static
        worker prompt and the engagement documents.  Wrapping an explicit
        mission in an additional generated playbook can silently change what
        the operator asked the first turn to do.
        """
        meta = self.ws.load_meta()
        if meta.last_directive and not self.brief:
            return meta.last_directive
        if self.brief:
            return self.brief
        return _RECOVERY_ACTION

    async def _run_turn_with_heartbeat(self, directive_text: str):
        """Run a worker turn while emitting a heartbeat so a long, silent turn
        (e.g. the first 258 MB resume + deep thinking) never looks hung."""
        self._turn_tool_count = 0
        start = time.time()
        task = asyncio.ensure_future(self.worker.run_turn(directive_text))
        last_heartbeat = start
        while not task.done():
            done, _ = await asyncio.wait({task}, timeout=1)
            if not done:
                if (self.ws.root / ".ledger" / "STOP").exists():
                    self.request_stop("external stop flag (`grypton stop`)")
                if self.stop_requested:
                    await self.worker.aclose()
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    raise asyncio.CancelledError(self.stop_reason or "stopped")
                if time.time() - last_heartbeat >= 10:
                    self.emit("heartbeat", elapsed=int(time.time() - start),
                              tools=self._turn_tool_count)
                    last_heartbeat = time.time()
        return task.result()

    @staticmethod
    def _worker_failure_tool_count(exc: Exception) -> int:
        """Read only the bounded replay-safety signal from provider metadata."""
        metadata = getattr(exc, "metadata", None)
        if not isinstance(metadata, dict):
            return 0
        tool_count = metadata.get("tool_count")
        if (
            isinstance(tool_count, bool)
            or not isinstance(tool_count, int)
            or tool_count <= 0
        ):
            return 0
        return min(tool_count, _MAX_WORKER_FAILURE_TOOL_COUNT)

    @staticmethod
    def _worker_failure_replay_unsafe(exc: Exception) -> bool:
        """Fail closed unless a worker provider proves no tool could have run."""
        if not isinstance(exc, WorkerError):
            return False
        metadata = exc.metadata if isinstance(exc.metadata, dict) else {}
        return metadata.get("replay_safe") is not True

    def _begin_worker_provider_window(self, *, turn: int, attempt: int) -> str:
        """Mark one supervised real-provider call before OpenCode can run."""
        if self.backend != "real":
            return ""
        if self._worker_provider_window_nonce:
            return self._worker_provider_window_nonce
        from .runtime import _provider_call_window_begin
        nonce = _provider_call_window_begin(
            self.slug,
            turn=turn,
            attempt=attempt,
        )
        self._worker_provider_window_nonce = nonce
        self._worker_provider_window_tainted = False
        return nonce

    def _complete_worker_provider_window(self, nonce: str) -> None:
        """Release a matching window after the completed turn is durable."""
        if not nonce:
            return
        from .runtime import (_provider_call_window_complete,
                              _sync_file_and_parent)
        # `_persist_turn` and Workspace.update_meta have both returned by this
        # point. Sync their files and directory entries before removing the
        # replay guard; any sync failure leaves the marker active.
        _sync_file_and_parent(self.ws.transcripts_dir / "turns.jsonl")
        _sync_file_and_parent(self.ws.meta_path)
        _provider_call_window_complete(self.slug, nonce)
        self._worker_provider_window_nonce = ""
        self._worker_provider_window_tainted = False

    def _release_replay_safe_worker_provider_window(self, nonce: str) -> bool:
        """Release a wholly replay-safe provider window before retry backoff."""
        if not nonce or self._worker_provider_window_tainted:
            return False
        from .runtime import _provider_call_window_complete
        _provider_call_window_complete(self.slug, nonce)
        self._worker_provider_window_nonce = ""
        self._worker_provider_window_tainted = False
        return True

    def _reset_worker_after_partial_failure(self) -> None:
        """Forget only Kraude's incomplete provider conversation."""
        self.ws.update_meta(turn_index=self.turn_index, worker_uuid="")
        worker = self.worker
        rollover = getattr(worker, "rollover_session", None)
        if callable(rollover):
            try:
                rollover()
            finally:
                # Keep the persisted empty ID authoritative even if a custom
                # worker hook fails partway through its local cleanup.
                worker.session_id = ""
                spec = getattr(worker, "spec", None)
                if spec is not None:
                    spec.session_uuid = ""
        else:
            worker.session_id = ""
            spec = getattr(worker, "spec", None)
            if spec is not None:
                spec.session_uuid = ""

    def _suppress_partial_worker_replay(
        self,
        current_directive: str,
        *,
        turn: int,
        attempt: int,
        tool_count: int,
        reason: str,
    ) -> str:
        """Replace a possibly effectful failed directive with a fresh action."""
        replacement = _PARTIAL_TOOL_RECOVERY_ACTION
        if replacement.strip() == str(current_directive or "").strip():
            replacement += " Choose another concrete surface item for this attempt."
        event = {
            "turn": turn,
            "attempt": attempt,
            "tool_count": tool_count,
            "reason": reason,
            "session_reset": True,
        }
        self.emit("worker_replay_suppressed", **event)
        if tool_count:
            basis = f"after {tool_count} observed tool event(s)"
        else:
            basis = "because native tool execution could not be ruled out"
        self.ws.append_progress(
            f"Attempt for turn {turn}: suppressed replay {basis}; "
            "Kraude will continue in a fresh session."
        )
        return replacement

    @staticmethod
    def _deadline_worker_retry(exc: Exception) -> Optional[dict]:
        """Classify one sanitized OpenClaude exhausted-pool worker failure.

        Generic exceptions and unstructured ``WorkerError`` instances stay on
        the finite fault path. This keeps coding/configuration mistakes from
        becoming an endless deadline-mode loop.
        """
        if not isinstance(exc, WorkerError):
            return None
        metadata = exc.metadata if isinstance(exc.metadata, dict) else {}
        if not (
            metadata.get("source") == "openclaude"
            and metadata.get("type") == "openclaude_terminal"
            and metadata.get("role") == "worker"
            and metadata.get("reason") == "credential_pool_exhausted"
        ):
            return None

        retry_after = metadata.get("retry_after_s")
        if (
            isinstance(retry_after, bool)
            or not isinstance(retry_after, int)
            or retry_after <= 0
        ):
            retry_after = _DEFAULT_WORKER_PROVIDER_RETRY_S
        wait_s = min(retry_after, _MAX_WORKER_PROVIDER_RETRY_S)

        status = metadata.get("upstream_status")
        if (
            isinstance(status, bool)
            or not isinstance(status, int)
            or not 100 <= status <= 599
        ):
            status = 0
        return {
            "wait_s": wait_s,
            "reason": "credential_pool_exhausted",
            "upstream_status": status,
        }

    async def _wait_for_worker_retry(self, delay_s: int) -> bool:
        """Wait for a retry while honoring engine stop and runtime deadline."""
        retry_deadline = time.monotonic() + max(0, delay_s)
        while not self.stop_requested:
            if (self.ws.root / ".ledger" / "STOP").exists():
                self._stop("external stop flag (`grypton stop`)")
                return False

            timeout = retry_deadline - time.monotonic()
            if timeout <= 0:
                return True

            max_run_seconds = config.CONFIG.max_run_seconds
            if max_run_seconds and self._start_time:
                run_remaining = max_run_seconds - (time.time() - self._start_time)
                if run_remaining <= 0:
                    self._stop("max_run_seconds safety ceiling reached")
                    return False
                timeout = min(timeout, run_remaining)

            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=min(timeout, _WORKER_RETRY_POLL_S),
                )
            except asyncio.TimeoutError:
                continue
            return False
        return False

    def _rollover_worker_session_if_needed(self, turn) -> bool:
        """Persist and clear an over-limit Kraude conversation between calls."""
        limit = getattr(config.CONFIG, "worker_context_rollover_tokens", 0)
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            return False
        result = getattr(turn, "result", None)
        if not isinstance(result, dict) or "context_tokens" not in result:
            return False
        context_tokens = result.get("context_tokens")
        if (
            isinstance(context_tokens, bool)
            or not isinstance(context_tokens, int)
            or context_tokens < limit
        ):
            return False
        worker = self.worker
        rollover = getattr(worker, "rollover_session", None)
        if not callable(rollover) or not getattr(worker, "session_id", ""):
            return False

        # Workspace metadata is an atomic replace. Persist the empty resumable ID
        # before changing in-memory state, with no await or provider call between
        # the two operations. A crash can therefore only resume fresh or retain
        # the still-valid old session; it cannot publish a half-written ID.
        self.ws.update_meta(turn_index=self.turn_index, worker_uuid="")
        rollover()
        # Keep the disk record authoritative even if a custom worker's rollover
        # hook is incomplete. The production hook also resets its token counter.
        worker.session_id = ""
        spec = getattr(worker, "spec", None)
        if spec is not None:
            spec.session_uuid = ""
        event = {
            "turn": self.turn_index,
            "context_tokens": context_tokens,
            "threshold": limit,
        }
        self.emit("worker_session_rollover", **event)
        self.ws.append_progress(
            f"Turn {self.turn_index}: Kraude context rolled over after "
            f"a reported {context_tokens}-token context footprint "
            f"(threshold {limit})."
        )
        return True

    def _build_context(self, turn, new_findings, flags, exhausted, user_msgs,
                       worker_was_idle=False, worker_idle_streak=0,
                       convergence_reason="", novel_finding_families=0,
                       coverage_priority="") -> ManagerContext:
        c = self.ws.load_constraints()
        return ManagerContext(
            target=self.target, target_type=self.target_type, turn_index=self.turn_index,
            constraints_block=c.to_prompt_block(),
            worker_last_text=(turn.assistant_text if turn else ""),
            worker_tool_summary=self._tool_summary(turn.tool_uses if turn else []),
            findings_summary=self._doc_tail(self.ws.root / "findings.md", 3000),
            finding_families=self.ws.finding_family_catalog(),
            surface_summary=self._doc_window(self.ws.root / "attack-surface.md", 3000),
            tested_summary=self._doc_window(self.ws.root / "tested-techniques.md", 2500),
            progress_tail=self._doc_tail(self.ws.root / "progress.md", 1500, tail=True),
            antifab_flags=flags,
            worker_was_idle=worker_was_idle, worker_idle_streak=worker_idle_streak,
            exhaustion=exhausted, exhaustion_streak=self._exhaustion_streak,
            network_calls=self._last_network_metrics["calls"],
            novel_network_signatures=self._last_network_metrics["novel"],
            repeated_network_calls=self._last_network_metrics["repeated"],
            over_limit_network_calls=self._last_network_metrics["over_limit"],
            passive_stagnation_streak=self._passive_stagnation_streak,
            repetitive_probe_streak=self._repetitive_probe_streak,
            convergence_reason=convergence_reason,
            user_messages=user_msgs, new_findings=new_findings,
            new_finding_cases=self._manager_case_projection(new_findings),
            novel_finding_families=novel_finding_families,
            family_stagnation_streak=self._family_stagnation_streak,
            coverage_priority=coverage_priority,
            validation_backlog=self._bounded_proof_backlog(),
            p1_count=len(self.ws.confirmed_p1s()),
        )

    @staticmethod
    def _trusted_astra_verdict(verdict: object) -> bool:
        return bool(
            isinstance(verdict, dict)
            and verdict.get("degraded", False) is False
            and str(verdict.get("validator_model") or "")
            == config.VALIDATOR_MODEL
            and str(verdict.get("validator_effort") or "")
            == config.VALIDATOR_EFFORT
        )

    @classmethod
    def _automatic_validation_candidates(cls, findings: list[dict]) -> list[dict]:
        terminal = {
            "confirm", "agree", "upgrade", "downgrade", "reject",
            "needs-more-evidence", "pending",
        }
        return [
            finding for finding in findings
            if finding.get("status") != "suppressed-by-scope"
            and (
                not isinstance(finding.get("manager_verdict"), dict)
                or finding.get("manager_verdict", {}).get("degraded") is True
                or not cls._trusted_astra_verdict(
                    finding.get("manager_verdict")
                )
                or str(finding.get("manager_verdict", {}).get(
                    "verdict") or "").strip().lower() not in terminal
            )
            and config.astra_auto_validation_required(finding.get("severity", ""))
        ]

    def _refresh_finding_records(self, findings: list[dict]) -> list[dict]:
        """Return current ledger versions of a turn's findings in original order."""
        current = {
            str(finding.get("id")): finding
            for finding in self.ws.findings.all()
            if finding.get("id")
        }
        return [current.get(str(finding.get("id")), finding) for finding in findings]

    def _validation_turn_findings(self, new_findings: list[dict]) -> list[dict]:
        """Include revisions and one durable Astra transport retry per turn."""
        self._selected_validation_retry_id = ""
        self._selected_validation_retry_epoch_max_id = ""
        current = self.ws.findings.all()
        by_id = {
            str(finding.get("id")): finding
            for finding in current
            if finding.get("id")
        }
        ordered = []
        seen: set[str] = set()
        for finding in new_findings:
            fid = str(finding.get("id") or "")
            if fid and fid not in seen:
                ordered.append(by_id.get(fid, finding))
                seen.add(fid)
        for finding in current:
            fid = str(finding.get("id") or "")
            if (
                fid
                and fid not in seen
                and str(finding.get(ASTRA_REVALIDATION_REVISION_FIELD) or "").strip()
                and self._automatic_validation_candidates([finding])
            ):
                ordered.append(finding)
                seen.add(fid)
        # A validator/provider outage or provenance-free legacy verdict is not
        # an Astra result. Retry one stranded candidate per completed worker
        # turn, including after an engine restart. Rotate durably so one
        # repeatable failure cannot starve later candidates. Trusted evidence
        # gaps stay out until Kraude attaches a material revision.
        retryable = []
        for finding in current:
            fid = str(finding.get("id") or "")
            if (
                fid and fid not in seen
                and self._automatic_validation_candidates([finding])
            ):
                retryable.append(finding)
        if retryable:
            selected_index, epoch_max_id = self._next_id_slot(
                retryable,
                self._validation_retry_after_id,
                self._validation_retry_epoch_max_id,
            )
            selected = retryable[selected_index]
            selected_id = str(selected.get("id") or "")
            ordered.append(selected)
            seen.add(selected_id)
            self._selected_validation_retry_id = selected_id
            self._selected_validation_retry_epoch_max_id = epoch_max_id
        return ordered

    @classmethod
    def _high_severity_proof_backlog(cls, findings: list[dict]) -> list[dict]:
        """Project durable Astra evidence gaps without forwarding case evidence."""
        backlog = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            if finding.get("status") == "suppressed-by-scope":
                continue
            claimed = str(finding.get("severity") or "").strip().upper()
            if not config.astra_auto_validation_required(claimed):
                continue
            verdict = finding.get("manager_verdict")
            if not cls._trusted_astra_verdict(verdict):
                continue
            if str(verdict.get("verdict") or "").strip().lower() not in {
                "needs-more-evidence", "pending",
            }:
                continue
            raw_checks = verdict.get("independent_checks")
            checks = raw_checks if isinstance(raw_checks, list) else []
            backlog.append({
                "id": safe_display_text(finding.get("id"), 32),
                "title": safe_display_text(finding.get("title"), 160),
                "claimed_severity": safe_display_text(claimed, 16),
                "astra_severity": safe_display_text(
                    verdict.get("severity"), 16,
                ),
                "surface": safe_display_text(finding.get("surface"), 180),
                "independent_checks": [
                    rendered for check in checks[:4]
                    if (rendered := safe_display_text(check, 240))
                ],
            })
        # Finding IDs are allocated monotonically. Keeping one stable order for
        # P1 and P2 prevents a stream of newly inserted P1 claims from starving
        # an older P2 evidence gap forever.
        backlog.sort(
            key=lambda row: Workspace._finding_id_sort_key(row["id"])
        )
        return backlog

    def _bounded_proof_backlog(self) -> list[dict]:
        """Return a rotating, prompt-sized view of every durable proof gap."""
        backlog = self._high_severity_proof_backlog(self.ws.findings.all())
        if not backlog:
            return []
        start, _epoch_max_id = self._next_proof_slot(backlog)
        return [
            backlog[(start + offset) % len(backlog)]
            for offset in range(min(len(backlog), _MAX_PROOF_BACKLOG))
        ]

    def _next_proof_slot(self, backlog: list[dict]) -> tuple[int, str]:
        """Select the next case inside a fixed round, then admit new IDs."""
        return self._next_id_slot(
            backlog,
            self._proof_rotation_after_id,
            self._proof_rotation_epoch_max_id,
        )

    @staticmethod
    def _next_id_slot(
        rows: list[dict],
        after_id: str,
        epoch_max_id: str,
    ) -> tuple[int, str]:
        """Advance within one fixed ID epoch so new arrivals cannot starve wrap."""
        if not rows:
            return 0, ""
        current_max_id = str(rows[-1].get("id") or "")
        active_epoch = epoch_max_id or current_max_id
        anchor = Workspace._finding_id_sort_key(after_id)
        epoch_tail = Workspace._finding_id_sort_key(active_epoch)
        for index, row in enumerate(rows):
            row_key = Workspace._finding_id_sort_key(row.get("id"))
            if row_key > anchor and row_key <= epoch_tail:
                return index, active_epoch
        # Every still-present row in the old epoch has received a slot. Freeze
        # the current tail for the next round, then revisit the oldest gap.
        return 0, current_max_id

    def _has_mobile_artifact(self) -> bool:
        if str(self.target_type or "").lower() in {"apk", "binary"}:
            return True
        if ".apk" in str(self.target or "").lower():
            return True
        for row in self.ws.surface.all()[-200:]:
            if not isinstance(row, dict):
                continue
            value = " ".join(str(row.get(key) or "") for key in (
                "kind", "item", "detail", "interesting",
            )).lower()
            if re.search(r"(?:\bapk\b|\.apk(?:\b|\?))", value):
                return True
        return False

    @staticmethod
    def _proof_priority(candidate: dict) -> str:
        if not candidate:
            return ""
        checks = candidate.get("independent_checks") or []
        if checks:
            rendered = "; ".join(
                f"({index}) {check}"
                for index, check in enumerate(checks, start=1)
            )
            action = f"perform every requested independent check: {rendered}"
        else:
            action = "capture the missing positive and control proof"
        return (
            f"For {candidate['id']}, {action}. Save the paired evidence and attach "
            "the material revision with revise_finding."
        )

    @staticmethod
    def _select_next_directive(
        directive,
        priority_selection: _PrioritySelection,
        *,
        force_recovery: bool = False,
    ) -> tuple[str, bool]:
        """Resolve scheduled engine work against Kryptex's chosen action.

        A proof-priority selection represents a concrete outstanding Astra
        evidence request, so its bounded cadence remains authoritative. A
        generic coverage rotation is only a recovery action: a healthy,
        executable Kryptex directive has more current evidence and keeps
        control. The boolean reports whether the scheduled priority was the
        action selected for Kraude.
        """
        manager_text = directive.worker_message() if directive is not None else ""
        priority = str(priority_selection.action or "").strip()
        kind = str(priority_selection.kind or "").strip().lower()

        if priority and kind == "proof":
            return priority, True

        manager_needs_recovery = (
            force_recovery
            or directive is None
            or bool(getattr(directive, "degraded", False))
            or _looks_like_idle_directive(manager_text)
            or _looks_like_soft_retreat_directive(manager_text)
        )
        if priority and kind == "coverage" and manager_needs_recovery:
            return priority, True
        if force_recovery:
            return "", False
        return manager_text, False

    def _next_coverage_priority(
        self,
        *,
        exhausted: bool,
        worker_was_idle: bool,
        convergence_reason: str,
    ) -> _PrioritySelection:
        backlog = self._high_severity_proof_backlog(self.ws.findings.all())
        # Proof acquisition has its own cadence. New lower-severity families do
        # not reset it, so a P1/P2 evidence request cannot be starved by endless
        # discovery. The cursor advances only when the selected directive and
        # next resume state are committed together below.
        if (
            backlog
            and self.turn_index > 0
            and self.turn_index % _PROOF_PRIORITY_FREQUENCY == 0
        ):
            candidate_index, epoch_max_id = self._next_proof_slot(backlog)
            candidate = backlog[candidate_index]
            candidate_id = str(candidate.get("id") or "")
            return _PrioritySelection(
                self._proof_priority(candidate),
                "proof",
                candidate_id,
                epoch_max_id,
            )
        if self._family_stagnation_streak < _FAMILY_PRIORITY_THRESHOLD:
            return _PrioritySelection()
        cursor = self._coverage_rotation_cursor
        capabilities = set()
        if exhausted or worker_was_idle or convergence_reason:
            capabilities.add("blocker")
        if self._has_mobile_artifact():
            capabilities.add("mobile_artifact")
        action = priority_action(
            self.target_type,
            cursor,
            capabilities=capabilities,
        )
        return _PrioritySelection(action, "coverage" if action else "")

    @staticmethod
    def _manager_case_projection(findings: list[dict]) -> list[dict]:
        """Keep new-case direction data useful without forwarding case evidence."""
        projected = []
        for finding in findings:
            verdict = finding.get("manager_verdict")
            astra = {}
            if isinstance(verdict, dict):
                checks = verdict.get("independent_checks")
                if not isinstance(checks, list):
                    checks = []
                astra = {
                    "verdict": str(verdict.get("verdict") or "")[:32],
                    "severity": str(verdict.get("severity") or "")[:16],
                    "independent_checks": [
                        str(check)[:300] for check in checks[:8]
                    ],
                }
            projected.append({
                "id": str(finding.get("id") or "")[:32],
                "title": str(finding.get("title") or "")[:300],
                "severity": str(finding.get("severity") or "")[:16],
                "status": str(finding.get("status") or "")[:64],
                "surface": str(finding.get("surface") or "")[:300],
                "astra": astra,
            })
        return projected

    async def _validate_with_stop(self, finding: dict, ctx: ManagerContext):
        """Run Astra while allowing a normal engine stop to cancel it promptly."""
        validation_task = asyncio.create_task(
            self.manager.validate_severity(finding, ctx)
        )
        stop_task = asyncio.create_task(self._stop_event.wait())
        try:
            done, _ = await asyncio.wait(
                {validation_task, stop_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if validation_task in done:
                return validation_task.result()

            validation_task.cancel()
            await asyncio.gather(validation_task, return_exceptions=True)
            validator = getattr(self.manager, "validator", None)
            cancel = getattr(validator, "cancel", None)
            if callable(cancel):
                await cancel()
            self.emit("status", text=(
                f"Astra validation for {finding.get('id') or '(unknown finding)'} "
                f"was stopped: {self.stop_reason or 'engine stop requested'}."
            ))
            return None
        except BaseException:
            if not validation_task.done():
                validation_task.cancel()
                await asyncio.gather(validation_task, return_exceptions=True)
            validator = getattr(self.manager, "validator", None)
            cancel = getattr(validator, "cancel", None)
            if callable(cancel):
                await cancel()
            raise
        finally:
            if not stop_task.done():
                stop_task.cancel()
            await asyncio.gather(stop_task, return_exceptions=True)

    def _apply_manager(self, directive, new_findings, ctx) -> None:
        if directive is None:
            return
        self.emit("manager", assessment=directive.assessment, directive=directive.directive,
                  corrections=directive.corrections, new_angles=directive.new_angles,
                  to_user=directive.to_user, degraded=getattr(directive, "degraded", False),
                  fallback_provider=getattr(directive, "fallback_provider", ""))
        # Apply severity verdicts from the directive, but DEDUP: skip ones that
        # would just re-affirm an already-decisive verdict at the same severity.
        # Without this, the manager re-validates the same finding every turn it
        # sees in the family catalog (observed: F001 got 6 identical
        # "Confirmed P2" appendices over the bugcrowd engagement).
        existing_by_id = {f["id"]: f for f in self.ws.findings.all()}
        validated = set()
        for v in directive.severity_validations:
            fid = v.get("finding_id")
            if not fid:
                continue
            existing = existing_by_id.get(fid, {})
            if self._verdict_is_redundant(existing.get("manager_verdict"), v):
                self.emit("status", text=(
                    f"Manager re-validated {fid} with the same "
                    f"{v.get('severity','?')}/{v.get('verdict','?')} verdict — "
                    f"skipped the duplicate append (engine dedup)."))
                continue
            self.ws.set_severity_verdict(fid, v)
            validated.add(fid)
            self.emit("verdict", finding_id=fid, verdict=v)

    @staticmethod
    def _verdict_is_redundant(existing, new) -> bool:
        """A new verdict is redundant if an EXISTING verdict is already decisive
        AND at the same severity. 'needs-more-evidence' / 'reject' / 'pending' /
        '' are NOT decisive — re-validation against fresh evidence is allowed
        there. A severity change ALWAYS goes through (upgrade/downgrade)."""
        if not isinstance(existing, dict) or not existing:
            return False
        ex_sev = (existing.get("severity") or "").upper()
        new_sev = (new.get("severity") or "").upper() if isinstance(new, dict) else ""
        ex_verdict = (existing.get("verdict") or "").lower()
        if ex_verdict not in ("confirm", "agree", "upgrade", "downgrade"):
            return False
        if ex_sev and new_sev and ex_sev != new_sev:
            return False    # severity change — let it through
        return True

    def _handle_p1s(self) -> None:
        p1s = self.ws.confirmed_p1s()
        if p1s:
            # compatibility marker some setups watch for
            try:
                (self.ws.root / ".ledger").mkdir(exist_ok=True)
                (self.ws.root / ".ledger" / "p1-found").write_text(str(time.time()))
            except OSError:
                pass

        threshold = str(config.CONFIG.until_severity or "").strip().upper()
        if threshold:
            matches = astra_confirmed_cases_at_or_above(
                self.ws.findings.all(), threshold
            )
            if matches:
                self._stop(
                    f"{len(matches)} Astra-confirmed case(s) at {threshold} or higher"
                )
            return

        # Preserve the original --stop-on-p1 behavior for existing finite runs.
        if p1s and config.CONFIG.stop_on_p1:
            self._stop(f"{len(p1s)} confirmed P1 case(s) and stop_on_p1 is set")

    # -------------------------------------------------------- introspection

    def _deltas(self):
        all_f = self.ws.findings.all()
        all_s = self.ws.surface.all()
        old_f, old_s = self._counts
        new_findings = all_f[old_f:]
        current_family_ids = self._finding_family_ids(all_f)
        new_family_ids = current_family_ids - self._active_family_ids
        new_rows = all_s[old_s:]
        self._raw_new_surface = len(new_rows)
        new_surface = 0
        for row in new_rows:
            key = self._surface_key(row)
            if key not in self._surface_keys:
                self._surface_keys.add(key)
                if not self._surface_is_bookkeeping(row):
                    new_surface += 1
        self._counts = (len(all_f), len(all_s))
        self._active_family_ids = current_family_ids
        return new_findings, new_family_ids, new_surface

    @staticmethod
    def _finding_family_ids(findings: list[dict]) -> set[str]:
        """Return active anchor IDs; every family is backed by at least one case."""
        return {
            family_id
            for finding in findings
            if finding.get("status") != "suppressed-by-scope"
            if (family_id := str(
                finding.get("family_id") or finding.get("id") or ""
            ).strip())
        }

    @staticmethod
    def _surface_key(row: dict) -> str:
        """Collapse counters and opaque hashes without merging real routes."""
        kind = re.sub(r"\s+", " ", str(row.get("kind") or "").strip().lower())
        item = re.sub(r"\s+", " ", str(row.get("item") or "").strip().lower())
        item = re.sub(r"\b([a-f0-9]{24,})\b", "{hash}", item)
        item = re.sub(
            r"(?i)\b(checkpoint|sentinel|interval)\s*(?:#|number)?\s*\d+\b",
            r"\1 {n}", item,
        )
        return f"{kind}::{item}"

    @staticmethod
    def _surface_is_bookkeeping(row: dict) -> bool:
        kind = str(row.get("kind") or "")
        item = str(row.get("item") or "")
        return bool(re.search(
            r"(?i)(?:checkpoint|sentinel|passive\s+(?:stability|hold)|"
            r"continuity\s+hold|hash\s+(?:watch|register|check)|ledger\s+integrity|"
            r"non[- ]finding|negative[- ]result)",
            f"{kind} {item}",
        ))

    @staticmethod
    def _network_signature(tool_use: dict) -> str:
        name = str(tool_use.get("name") or "").lower()
        name = name.removeprefix("grypton_")
        network_tools = {
            "http_request", "goja_request", "flow_replay", "httpx_probe",
            "browse", "dns_lookup", "tls_certificate", "port_scan",
            "subdomain_enum", "credential_login", "credential_browser_login",
            "authenticated_http_request", "authenticated_browser_request",
            "artifact_download", "tcp_exchange", "research",
        }
        if name not in network_tools:
            return ""
        args = tool_use.get("input") if isinstance(tool_use.get("input"), dict) else {}
        request_tools = {
            "http_request", "goja_request", "flow_replay", "browse",
            "authenticated_http_request", "authenticated_browser_request",
        }
        method = str(
            args.get("method") or ("GET" if name in request_tools else name)
        ).upper()
        raw_url = str(args.get("url") or "")
        if raw_url:
            # Tool arguments are historical model output and therefore an
            # untrusted input boundary.  In particular, a browser may record a
            # local ``data:text/html,...`` document.  Treating that value as a
            # scheme-less host turns ``text`` into a purported port and makes
            # ``SplitResult.port`` raise ValueError while an engine resume is
            # rebuilding its novelty counters.  Local/non-web schemes are not
            # network probes, so omit them.  Malformed HTTP(S) values likewise
            # cannot contribute a useful, stable signature.
            value = raw_url.strip()
            lower_value = value.casefold()
            if lower_value.startswith(("http://", "https://", "//")):
                candidate = value
            elif re.match(r"^[a-z][a-z0-9+.-]*:", value, re.IGNORECASE):
                # Preserve the common scheme-less ``host:port/path`` form.
                # Every other explicit scheme (data:, blob:, about:, file:,
                # javascript:, and unknown schemes) is local/non-HTTP here.
                possible_host, after_colon = value.split(":", 1)
                host_like = (
                    "." in possible_host
                    or possible_host.casefold() == "localhost"
                )
                candidate = (
                    "//" + value
                    if host_like and after_colon.partition("/")[0].isdigit()
                    else ""
                )
            else:
                candidate = "//" + value
            if not candidate:
                return ""
            try:
                split = urlsplit(candidate)
                scheme = split.scheme.lower() or "https"
                host = (split.hostname or "").lower().rstrip(".")
                parsed_port = split.port
            except (TypeError, ValueError):
                return ""
            if scheme not in {"http", "https"} or not host:
                return ""
            port = f":{parsed_port}" if parsed_port else ""
            path = re.sub(r"/+", "/", split.path or "/")
            query_keys = sorted({key for key, _ in parse_qsl(split.query, keep_blank_values=True)})
            shape = f"{scheme}://{host}{port}{path}"
            if query_keys:
                shape += "?" + "&".join(query_keys)
        elif name == "flow_replay":
            shape = f"flow:{args.get('flow_id') or ''}"
        elif name == "httpx_probe":
            shape = "targets:" + " ".join(sorted(str(args.get("targets") or "").split()))
        else:
            host = str(args.get("host") or args.get("domain") or "").lower().rstrip(".")
            extra = ""
            if name == "port_scan":
                extra = ":" + ",".join(str(p) for p in sorted(args.get("ports") or []))
            elif name == "tls_certificate":
                extra = ":" + str(args.get("port") or 443)
            shape = host + extra
        return f"{name}|{method}|{shape}"

    def _network_novelty(self, tool_uses: list[dict]) -> dict:
        metrics = {"calls": 0, "novel": 0, "repeated": 0, "over_limit": 0,
                   "signatures": []}
        limit = max(1, int(config.CONFIG.probe_repeat_limit))
        for tool_use in tool_uses:
            signature = self._network_signature(tool_use)
            if not signature:
                continue
            prior = self._network_signatures[signature]
            metrics["calls"] += 1
            if prior == 0:
                metrics["novel"] += 1
            else:
                metrics["repeated"] += 1
            if prior >= limit:
                metrics["over_limit"] += 1
            self._network_signatures[signature] += 1
            metrics["signatures"].append(signature)
        self._last_network_metrics = metrics
        return metrics

    def _rehydrate_novelty_state(self) -> None:
        self._surface_keys = {self._surface_key(row) for row in self.ws.surface.all()}
        self._network_signatures.clear()
        path = self.ws.transcripts_dir / "turns.jsonl"
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return
        for line in lines:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            for tool_use in row.get("tools") or []:
                signature = self._network_signature(tool_use)
                if signature:
                    self._network_signatures[signature] += 1

    def _convergence_reason(self) -> str:
        repeat_limit = max(1, int(config.CONFIG.repetitive_probe_turn_limit))
        passive_limit = max(1, int(config.CONFIG.passive_stagnation_limit))
        if self._repetitive_probe_streak >= repeat_limit:
            return (
                f"{self._repetitive_probe_streak} consecutive turns used no new "
                "network request signature"
            )
        if self._passive_stagnation_streak >= passive_limit:
            return (
                f"{self._passive_stagnation_streak} consecutive turns produced no "
                "new finding family, novel surface, or new network request signature"
            )
        return ""

    @staticmethod
    def _tool_summary(tool_uses) -> str:
        if not tool_uses:
            return ""
        lines = []
        for t in tool_uses[:40]:
            inp = t.get("input")
            preview = ""
            if isinstance(inp, dict):
                for k in ("command", "url", "file_path", "query", "pattern"):
                    if k in inp:
                        preview = f" {k}={str(inp[k])[:120]}"
                        break
            lines.append(f"- {t.get('name')}{preview}")
        if len(tool_uses) > 40:
            lines.append(f"- … +{len(tool_uses) - 40} more")
        return "\n".join(lines)

    @staticmethod
    def _doc_tail(path: Path, budget: int, tail: bool = False) -> str:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        if len(text) <= budget:
            return text
        return ("…\n" + text[-budget:]) if tail else (text[:budget] + "\n…")

    @staticmethod
    def _doc_window(path: Path, budget: int) -> str:
        """Keep document framing plus the newest rows within one fixed budget."""
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        if len(text) <= budget:
            return text
        head = max(200, budget // 3)
        tail = max(0, budget - head - 3)
        return text[:head] + "\n…\n" + text[-tail:]

    def _persist_turn(self, turn) -> None:
        import json as _json
        rec = {"turn": self.turn_index, "ts": time.time(),
               "assistant_text": turn.assistant_text, "tools": turn.tool_uses,
               "is_error": turn.is_error, "cost_usd": turn.cost_usd}
        p = self.ws.transcripts_dir / "turns.jsonl"
        with p.open("a", encoding="utf-8") as f:
            f.write(_json.dumps(rec, ensure_ascii=False) + "\n")

    # ---------------------------------------------------- user interaction

    def submit_user(self, text: str, to_worker: bool = False) -> None:
        if to_worker:
            self.ws.add_standing_instruction(text)
        (self._user_to_worker if to_worker else self._user_to_manager).put_nowait(text)
        self.emit("user_echo", text=text, to_worker=to_worker)

    def current_models(self) -> dict[str, dict[str, str]]:
        return {
            "kraude": {"route": self.worker_model, "effort": self.worker_effort},
            "kryptex": {"route": self.manager_model, "effort": self.manager_effort},
            "validator": {
                "route": config.VALIDATOR_MODEL,
                "effort": config.VALIDATOR_EFFORT,
            },
        }

    def request_model_switch(self, role: str, route: str, effort: str = "") -> None:
        """Queue a validated-at-boundary role change from the synchronous console."""
        normalized = str(role or "").strip().lower()
        normalized = {"worker": "kraude", "manager": "kryptex"}.get(normalized, normalized)
        if normalized not in {"kraude", "kryptex"}:
            raise ValueError("role must be kraude or kryptex")
        requested = str(route or "").strip()
        if not requested:
            raise ValueError("a model route is required")
        self._model_switches.put_nowait({
            "role": normalized,
            "route": requested,
            "effort": str(effort or "").strip(),
            "requested_at": time.time(),
        })
        self.emit("status", text=(
            f"Queued {normalized} model change to {requested}"
            + (f" · {effort}" if effort else "")
            + "; it will apply at the next safe role boundary."
        ))

    async def _apply_pending_model_switches(self) -> None:
        from .openclaude import resolve_model

        while not self._model_switches.empty():
            try:
                request = self._model_switches.get_nowait()
            except asyncio.QueueEmpty:
                return
            role = request["role"]
            try:
                selection = await asyncio.to_thread(
                    resolve_model,
                    request["route"],
                    effort=request["effort"] or None,
                    require_tools=role == "kraude",
                )
                route = selection.route_id
                effort = selection.effort
                if role == "kraude":
                    if hasattr(self.worker, "switch_model"):
                        await self.worker.switch_model(route, effort)
                    self.worker_model, self.worker_effort = route, effort
                    self.ws.update_meta(
                        worker_model=route,
                        worker_effort=effort,
                        worker_uuid=getattr(self.worker, "session_id", "") or "",
                    )
                else:
                    async with self._mgr_lock:
                        if hasattr(self.manager, "switch_model"):
                            await self.manager.switch_model(route, effort)
                    self.manager_model, self.manager_effort = route, effort
                    self.ws.update_meta(
                        manager_model=route,
                        manager_effort=effort,
                        manager_session_id=getattr(self.manager, "session_id", "") or "",
                    )
                from .providers import append_jsonl
                append_jsonl(self.ws.root / ".ledger" / "model-switches.jsonl", {
                    "at": time.time(),
                    "turn": self.turn_index,
                    "role": role,
                    "route": route,
                    "effort": effort,
                    "source": "operator",
                })
                self.emit("model_switch", role=role, route=route, effort=effort)
            except Exception as exc:
                self.emit("error", text=f"Could not switch {role} model: {exc}")

    def request_stop(self, reason: str = "user requested stop") -> None:
        self.stop_requested = True
        self.stop_reason = reason
        self._stop_event.set()

    @staticmethod
    def _drain(q: asyncio.Queue) -> list[str]:
        out = []
        while not q.empty():
            try:
                out.append(q.get_nowait())
            except asyncio.QueueEmpty:
                break
        return out

    def _prepend_user_to_worker(self, directive_text: str) -> str:
        msgs = self._drain(self._user_to_worker)
        if not msgs:
            return directive_text
        # A direct operator action or sanitized Kryptex relay supersedes the
        # queued manager action for this turn. Forward its text without adding
        # another instruction wrapper around it.
        relayed = "\n".join(
            str(message).strip() for message in msgs if str(message).strip()
        )
        return relayed or directive_text

    @staticmethod
    def _is_hard_stop(reason: str, *, convergence_allowed: bool = False) -> bool:
        r = (reason or "").lower()
        boundary = any(k in r for k in (
            "scope", "authoriz", "authoris", "permission", "illegal", "ethic",
            "out-of-scope", "out of scope", "unauthorized", "forbidden",
            "automation prohibited", "automation ban",
        ))
        converged = convergence_allowed and any(k in r for k in (
            "convergence", "exhaust", "defense ceiling", "no safe novel",
        ))
        return boundary or converged

    @staticmethod
    def _boundary_text_contains(text: str, recorded_value: str) -> bool:
        """Match one recorded boundary value without interpreting model prose."""
        recorded = " ".join(str(recorded_value or "").split())
        if "://" in recorded:
            # Reuse the network-tool scope policy so a manager citation and an
            # actual request agree on repeated decoding and dot-segment rules.
            from .tools import _canonical_url_path, _url_matches_rule

            try:
                expected = urlsplit(recorded)
                expected.port
            except ValueError:
                return False
            if expected.scheme.casefold() not in {"http", "https"} or not expected.hostname:
                return False
            if expected.username is not None or expected.password is not None:
                return False

            for raw in _URL_CITATION_RX.findall(str(text or "")):
                candidate_text = raw.rstrip(".,;!?")
                try:
                    candidate = urlsplit(candidate_text)
                    candidate_port = candidate.port
                except ValueError:
                    continue
                if candidate.username is not None or candidate.password is not None:
                    continue
                candidate_scheme = candidate.scheme.casefold()
                if candidate_scheme not in {"http", "https"} or not candidate.hostname:
                    continue
                candidate_port = candidate_port or {"http": 80, "https": 443}.get(
                    candidate_scheme
                )
                candidate_path = _canonical_url_path(candidate.path or "/")
                if candidate_port is None or candidate_path is None:
                    continue
                if _url_matches_rule(
                    candidate, candidate_port, candidate_path, recorded
                ):
                    return True
            return False

        haystack = " ".join(str(text or "").casefold().split())
        needle = " ".join(recorded.casefold().split()).rstrip("/")
        if not needle:
            return False
        # Do not let a recorded host/path prefix authorize a model-supplied
        # lookalike (`example.test.evil`, `/privateer`). URL separators still
        # allow a recorded host to be cited with a child path or query.
        pattern = rf"(?<![a-z0-9._~%:@-]){re.escape(needle)}(?![a-z0-9._~%:@-])"
        return bool(re.search(pattern, haystack))

    def _matches_recorded_deadline_boundary(self, directive) -> bool:
        """Return whether a model stop cites a binding recorded boundary.

        Deadline mode intentionally does not infer authority from generic words
        such as ``authorization``, ``permission``, or ``scope``.  It accepts an
        out-of-scope stop only when the directive cites an exact entry from the
        structured out-of-scope list.  An automation prohibition must likewise
        exist in the recorded hard rules and in the stop directive.  External
        stop flags and runtime ceilings bypass this method
        and remain binding in the main loop.
        """
        reason = str(getattr(directive, "stop_reason", "") or "")
        if not reason:
            return False
        constraints = self.ws.load_constraints()

        explicit_scope_claim = any(
            not _NEGATED_BOUNDARY_PREFIX_RX.search(reason[:match.start()])
            for match in _EXPLICIT_OUT_OF_SCOPE_RX.finditer(reason)
        )
        if explicit_scope_claim:
            if any(
                self._boundary_text_contains(reason, item)
                for item in constraints.out_of_scope
            ):
                return True

        recorded_automation_ban = any(
            _AUTOMATION_PROHIBITION_RX.search(str(rule or ""))
            for rule in constraints.hard_rules
        )
        return bool(
            recorded_automation_ban
            and _AUTOMATION_PROHIBITION_RX.search(reason)
        )

    def _manager_stop_is_binding(self, directive, *, convergence_reason: str = "") -> bool:
        """Classify a manager-requested stop for this engine run mode."""
        if self.run_until_stopped:
            return False
        if self.run_until_deadline:
            return self._matches_recorded_deadline_boundary(directive)
        return self._is_hard_stop(
            getattr(directive, "stop_reason", ""),
            convergence_allowed=bool(convergence_reason),
        )

    def _stop(self, reason: str) -> None:
        self.stop_requested = True
        self.stop_reason = reason
        self._stop_event.set()
        self.emit("status", text=f"STOPPING: {reason}")

    async def _teardown(self, *, status: str = "stopped") -> None:
        """Close every provider even when metadata or chat cleanup fails."""
        async with self._teardown_lock:
            if self._teardown_complete:
                return
            self.running = False
            chat_task = self._user_chat_task
            if chat_task and not chat_task.done():
                chat_task.cancel()
                try:
                    await asyncio.gather(chat_task, return_exceptions=True)
                except BaseException:
                    pass
            try:
                (self.ws.root / ".ledger" / "STOP").unlink(missing_ok=True)
            except OSError:
                pass

            # Provider teardown comes before bookkeeping: a corrupt/unwritable
            # workspace must never leave authenticated sidecars running.
            try:
                if self.worker:
                    await self.worker.aclose()
            except BaseException:
                pass
            try:
                if self.manager and hasattr(self.manager, "aclose"):
                    await self.manager.aclose()
            except BaseException:
                pass
            try:
                self.ws.update_meta(
                    status=status, turn_index=self.turn_index,
                    worker_uuid=getattr(self.worker, "session_id", "") or "",
                    manager_session_id=getattr(self.manager, "session_id", "") or "",
                    worker_model=self.worker_model, worker_effort=self.worker_effort,
                    manager_model=self.manager_model, manager_effort=self.manager_effort,
                )
            except (OSError, RuntimeError, TypeError, ValueError):
                pass
            self._teardown_complete = True
            try:
                self.emit("status", text=f"Engine stopped after {self.turn_index} turn(s). "
                          f"Reason: {self.stop_reason or 'n/a'}")
            except Exception:
                pass

    # ------------------------------------------------------------- events

    def _recovery_directive(self) -> str:
        """Reuse an explicit mission exactly; otherwise supply one positive action."""
        return self.brief if self.brief else _RECOVERY_ACTION

    def _continuation_directive(self) -> str:
        """Advance a timed run without replaying an already-completed mission.

        The operator's brief is still delivered verbatim on the opening turn.
        A detached deadline run can outlive that one-shot task, so a manager
        soft stop or idle response advances to the generic positive action
        instead of repeatedly submitting credentials or
        replaying another completed setup step.
        """
        return _RECOVERY_ACTION if self.run_until_deadline else self._recovery_directive()

    def _forced_action_directive_with_user_intent(self) -> str:
        """Compatibility wrapper for the former forced-action helper."""
        return self._recovery_directive()

    def _on_worker_event(self, evt: dict) -> None:
        etype = evt.get("type")
        if isinstance(etype, str) and etype.startswith("openclaude_"):
            self.emit("gateway", role="Kraude", event=evt)
        elif etype == "stream_event":
            inner = evt.get("event") or {}
            if inner.get("type") == "content_block_delta":
                delta = inner.get("delta") or {}
                dt = delta.get("type")
                if dt == "text_delta" and delta.get("text"):
                    self.emit("worker_delta", text=delta["text"])
                elif dt == "thinking_delta" and delta.get("thinking"):
                    self.emit("worker_thinking", text=delta["thinking"])
        elif etype == "assistant":
            for block in (evt.get("message") or {}).get("content", []) or []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_use":
                    self._turn_tool_count += 1
                    self.emit("worker_tool", name=block.get("name"), input=block.get("input"))
        elif etype == "user":
            for block in (evt.get("message") or {}).get("content", []) or []:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    self.emit("worker_tool_result",
                              content=_tool_result_text(block.get("content")),
                              is_error=bool(block.get("is_error")))
        elif etype == "system" and evt.get("subtype") == "init":
            self.emit("worker_system", model=evt.get("model"),
                      tools=len(evt.get("tools") or []),
                      mcp=[s.get("name") for s in (evt.get("mcp_servers") or []) if isinstance(s, dict)],
                      session=evt.get("session_id"))

    def _on_manager_event(self, evt: dict) -> None:
        if not isinstance(evt, dict):
            return
        t = evt.get("type")
        if t == "manager_event":
            inner = evt.get("event") if isinstance(evt.get("event"), dict) else {}
            if str(inner.get("type") or "").startswith("openclaude_"):
                self.emit("gateway", role="Kryptex", event=inner)
            else:
                self.emit("manager_provider", kind=inner.get("type", "event"), event=inner)
        elif t == "manager_fallback":
            self.emit("manager_fallback", via=evt.get("via", "deterministic"),
                      reason=evt.get("reason", ""))

    # ------------------------------------------------- real-time user chat

    async def _user_chat_loop(self) -> None:
        """Handle user→Kryptex messages in real time, concurrent with worker turns."""
        while not self.stop_requested:
            try:
                msg = await asyncio.wait_for(self._user_to_manager.get(), timeout=2.0)
            except asyncio.TimeoutError:
                continue
            except Exception:
                return
            # ALWAYS persist the user's verbatim message as a standing instruction
            # FIRST — even if Kryptex's chat call fails or reframes the wording, the
            # user's literal intent is captured as the highest-authority signal.
            self.ws.add_standing_instruction(f'[USER, turn ~{self.turn_index}] {msg.strip()}')
            self.emit("status", text="Kryptex is reading your message…")
            try:
                async with self._mgr_lock:
                    reply = await self.manager.chat(msg, self._chat_context())
            except Exception as e:
                self.emit("error", text=f"Kryptex chat error: {e}")
                self._user_to_worker.put_nowait(msg)
                continue
            self.emit("kryptex_chat", reply=reply.get("reply", ""),
                      disposition=reply.get("disposition", ""),
                      remember=reply.get("remember", ""),
                      degraded=reply.get("degraded", False))
            note = (reply.get("worker_note") or "").strip()
            disp = reply.get("disposition", "remember-only")
            if note and disp in ("apply-now", "apply-next-turn"):
                from .manager import Directive
                action = Directive(directive=note).worker_message()
                if action:
                    self._user_to_worker.put_nowait(action)

    def _chat_context(self) -> ManagerContext:
        return self._build_context(None, [], [], False, [])
