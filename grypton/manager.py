"""Kryptex manager and independent finding validation.

Kryptex receives the worker's complete turn summary in a fresh OpenCode session
and returns a bounded JSON directive. Its operator chat is persistent so a human
conversation can continue across turns. Finding severity is deliberately outside
both paths: P1 and P2 findings are reviewed
automatically by a fresh, tool-disabled GPT-6 Astra process. Lower severities
reach Astra only after an explicit operator request.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import json
import math
from pathlib import Path
import re
import time
from typing import Any, Callable, Optional

from . import config
from .providers import CodexValidator, OpenCodeClient, ProviderError


_DIRECTIVE_SENTENCE = re.compile(r"(?<=[.!?])(?:\s+|$)|\n+")
_PROHIBITIVE_DIRECTIVE = re.compile(
    r"^(?:[-*]\s*)?(?:do\s+not|don't|never|avoid|refrain\s+from|must\s+not|"
    r"no\s+(?:retry|retries|brute|bruteforce|brute-force|probing|testing|request|requests))\b",
    re.IGNORECASE,
)
_PROHIBITIVE_CLAUSE_BOUNDARY = re.compile(
    r"\s*(?:;|—|–|,?\s+\b(?:and|but)\b)\s*"
    r"(?=(?:do\s+not|don't|never|avoid|refrain\s+from|must\s+not|"
    r"no\s+(?:retry|retries|brute|bruteforce|brute-force|probing|testing|request|requests))\b)",
    re.IGNORECASE,
)

_MAX_PROVIDER_RETRY_S = 7 * 24 * 60 * 60
_DEFAULT_PROVIDER_RETRY_S = 60

_VALIDATOR_URL = re.compile(r"https?://[^\s,;`'\"<>]+", re.IGNORECASE)
_VALIDATOR_FENCE = re.compile(r"```.*?```", re.DOTALL)
_VALIDATOR_COMMAND = re.compile(
    r"(?im)^\s*(?:curl|wget|httpx|nmap|sqlmap|ffuf|nikto|adb|apktool)\b.*$"
)
_VALIDATOR_TOOL_NAME = re.compile(
    r"(?i)\b(?:curl|wget|httpx|nmap|sqlmap|ffuf|nikto|adb|apktool)\b"
)
_VALIDATOR_MARKUP = re.compile(r"<[^>\n]{1,500}>")
_VALIDATOR_EMAIL = re.compile(r"\b[^\s@]+@[^\s@]+\.[A-Za-z]{2,}\b")
_VALIDATOR_PHONE = re.compile(r"(?<!\d)(?:\+?98|0)?9\d{9}(?!\d)")
_VALIDATOR_HOST = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d+)?\b"
)
_VALIDATOR_IPV4 = re.compile(
    r"(?<!\d)(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\."
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?::\d+)?(?!\d)"
)
_VALIDATOR_LONG_VALUE = re.compile(r"\b[A-Za-z0-9_+/=-]{48,}\b")
_VALIDATOR_ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9_.-])/(?:[A-Za-z0-9_.~!$&'()*+,;=:@%\-]+/?){1,}"
)


def _validator_safe_text(value: object, *, limit: int = 8000) -> str:
    """Keep adjudication facts while removing live operational detail.

    Astra only decides evidence sufficiency and severity. It does not need a
    target hostname, credential, executable command, payload, or exact route.
    Removing those values also prevents captured pages from becoming prompt
    instructions and lets the validator run under standard safeguards.
    """
    text = str(value or "").replace("\x00", "")
    text = _VALIDATOR_FENCE.sub("[technical reproduction block omitted]", text)
    text = _VALIDATOR_COMMAND.sub("[reproduction command omitted]", text)
    text = _VALIDATOR_TOOL_NAME.sub("[REPRODUCTION_TOOL]", text)
    text = _VALIDATOR_URL.sub("[IN_SCOPE_URL]", text)
    text = _VALIDATOR_EMAIL.sub("[EMAIL]", text)
    text = _VALIDATOR_PHONE.sub("[PHONE]", text)
    text = _VALIDATOR_HOST.sub("[HOST]", text)
    text = _VALIDATOR_IPV4.sub("[HOST]", text)
    text = _VALIDATOR_LONG_VALUE.sub("[LONG_VALUE]", text)
    text = _VALIDATOR_MARKUP.sub("[MARKUP]", text)
    text = _VALIDATOR_ABSOLUTE_PATH.sub("[IN_SCOPE_PATH]", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) <= limit:
        return text
    marker = "\n[abstracted text truncated]\n"
    room = max(0, limit - len(marker))
    return text[: room // 2].rstrip() + marker + text[-(room - room // 2):].lstrip()


def _affirmative_directive(text: str) -> str:
    """Keep Kryptex's executable action without forwarding generated prohibitions."""
    parts = []
    for value in _DIRECTIVE_SENTENCE.split(str(text or "")):
        for clause in _PROHIBITIVE_CLAUSE_BOUNDARY.split(value):
            clause = clause.strip()
            if clause and not _PROHIBITIVE_DIRECTIVE.match(clause):
                parts.append(clause)
    action = " ".join(parts).strip()
    # Spark occasionally spells the Grypton MCP prefix as "gryphon". Keep the
    # action intact while mapping that typo to the installed tool namespace.
    return re.sub(r"\bgryphon_(?=[a-z])", "grypton_", action, flags=re.IGNORECASE)


@dataclass
class ManagerContext:
    target: str
    target_type: str
    turn_index: int
    constraints_block: str = ""
    worker_last_text: str = ""
    worker_tool_summary: str = ""
    findings_summary: str = ""
    finding_families: list[dict] = field(default_factory=list)
    surface_summary: str = ""
    tested_summary: str = ""
    progress_tail: str = ""
    antifab_flags: list[str] = field(default_factory=list)
    worker_was_idle: bool = False
    worker_idle_streak: int = 0
    exhaustion: bool = False
    exhaustion_streak: int = 0
    network_calls: int = 0
    novel_network_signatures: int = 0
    repeated_network_calls: int = 0
    over_limit_network_calls: int = 0
    passive_stagnation_streak: int = 0
    repetitive_probe_streak: int = 0
    convergence_reason: str = ""
    user_messages: list[str] = field(default_factory=list)
    new_findings: list[dict] = field(default_factory=list)
    new_finding_cases: list[dict] = field(default_factory=list)
    novel_finding_families: int = 0
    family_stagnation_streak: int = 0
    coverage_priority: str = ""
    validation_backlog: list[dict] = field(default_factory=list)
    p1_count: int = 0


@dataclass
class Directive:
    assessment: str = ""
    directive: str = ""
    corrections: list[str] = field(default_factory=list)
    new_angles: list[str] = field(default_factory=list)
    exhaustion_breaker: str = ""
    scope_enforcement: list[str] = field(default_factory=list)
    severity_validations: list[dict] = field(default_factory=list)
    to_user: str = ""
    cont: bool = True
    stop_reason: str = ""
    confidence: float = 0.0
    raw: dict = field(default_factory=dict)
    degraded: bool = False
    fallback_provider: str = ""

    def worker_message(self) -> str:
        # The structured fields remain available to the engine and UI. Kraude
        # receives one executable manager action rather than a generated stack
        # of corrections, prohibitions, and restated scope rules.
        return _affirmative_directive(self.directive)


def _extract_json(text: str) -> dict:
    """Extract the first balanced JSON object, allowing fenced model output."""
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise ValueError("response did not contain a JSON object")


def _check_schema(value: Any, schema: dict, path: str = "$") -> list[str]:
    """Small strict validator for the repository's three JSON schemas."""
    errors: list[str] = []
    expected = schema.get("type")
    type_ok = {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "boolean": isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
    }.get(expected, True)
    if not type_ok:
        return [f"{path}: expected {expected}"]
    if expected == "object":
        required = set(schema.get("required", []))
        missing = required.difference(value)
        errors.extend(f"{path}: missing {key}" for key in sorted(missing))
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            errors.extend(f"{path}: unexpected {key}" for key in value if key not in properties)
        for key, child in properties.items():
            if key in value:
                errors.extend(_check_schema(value[key], child, f"{path}.{key}"))
    elif expected == "array":
        child = schema.get("items", {})
        for index, item in enumerate(value):
            errors.extend(_check_schema(item, child, f"{path}[{index}]"))
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value is outside enum")
    return errors


class KryptexManager:
    def __init__(
        self,
        workspace,
        system_prompt: str,
        on_event: Optional[Callable[[dict], None]] = None,
        manager_kind: str = "",
        manager_model: str = "",
        manager_effort: str = "",
    ):
        self.ws = workspace
        self.system_prompt = system_prompt
        self.on_event = on_event
        self.manager_kind = manager_kind or "opencode+openclaude"
        self.manager_model = manager_model or config.MANAGER_MODEL
        self.manager_effort = manager_effort or config.MANAGER_EFFORT
        self.session_id = ""
        self._provider_circuit_until = 0.0
        self._direction_call_active = False
        self.directive_schema = self._load_schema("directive_schema.json")
        self.chat_schema = self._load_schema("chat_schema.json")
        self.severity_schema = self._load_schema("severity_schema.json")
        self.client = self._new_client()
        self.validator = CodexValidator(self.ws.root, self.ws.slug)

    def _new_client(self) -> OpenCodeClient:
        return OpenCodeClient(
            role="manager",
            route=self.manager_model,
            effort=self.manager_effort,
            workspace=self.ws.root,
            target_slug=self.ws.slug,
            allow_tools=False,
            agent_prompt=self.system_prompt,
            event_callback=self._provider_event,
        )

    async def switch_model(self, model: str, effort: str) -> None:
        """Change Kryptex between calls without carrying vendor-specific history."""
        await self.client.cancel()
        self.manager_model = model
        self.manager_effort = effort
        self.session_id = ""
        self._provider_circuit_until = 0.0
        self._direction_call_active = False
        self.client = self._new_client()

    @staticmethod
    def _load_schema(name: str) -> dict:
        path = config.PROMPTS_DIR / name
        return json.loads(path.read_text(encoding="utf-8"))

    def _provider_event(self, event: dict) -> None:
        if self.on_event:
            self.on_event({"type": "manager_event", "event": event})

    def _arm_provider_circuit(self, exc: ProviderError) -> bool:
        """Remember a structured exhausted-pool result without parsing prose."""
        metadata = exc.metadata
        if not (
            metadata.get("source") == "openclaude"
            and metadata.get("type") == "openclaude_terminal"
            and metadata.get("role") == "manager"
            and metadata.get("reason") == "credential_pool_exhausted"
        ):
            return False
        try:
            retry_after_s = int(metadata.get("retry_after_s") or 0)
        except (TypeError, ValueError):
            retry_after_s = 0
        if not 0 < retry_after_s <= _MAX_PROVIDER_RETRY_S:
            retry_after_s = _DEFAULT_PROVIDER_RETRY_S
        self._provider_circuit_until = time.monotonic() + retry_after_s
        return True

    def _clear_provider_circuit(self) -> None:
        self._provider_circuit_until = 0.0

    def _provider_retry_delay(self, exc: ProviderError) -> int | None:
        """Arm the pool circuit and return its bounded, sanitized wait."""
        if not self._arm_provider_circuit(exc):
            return None
        return max(
            1,
            min(
                _MAX_PROVIDER_RETRY_S,
                math.ceil(self._provider_circuit_until - time.monotonic()),
            ),
        )

    def _begin_direction_call(self) -> str:
        """Reserve the sole autonomous direction probe or describe why it is skipped."""
        remaining = self._provider_circuit_until - time.monotonic()
        if remaining > 0:
            return (
                "Kryptex provider pool is cooling down after credential exhaustion; "
                f"the next half-open probe is due in {math.ceil(remaining)} seconds."
            )
        self._provider_circuit_until = 0.0
        if self._direction_call_active:
            return "A Kryptex autonomous direction probe is already in progress."
        self._direction_call_active = True
        return ""

    async def _call_json(
        self,
        prompt: str,
        schema: dict,
        purpose: str,
        *,
        persistent_session: bool,
    ) -> dict:
        async def provider_call(current_prompt: str, session_id: str, title: str):
            while True:
                try:
                    result = await self.client.call(
                        current_prompt, session_id=session_id, title=title,
                    )
                except ProviderError as exc:
                    retry_after_s = self._provider_retry_delay(exc)
                    if retry_after_s is None:
                        raise
                    metadata = exc.metadata
                    if self.on_event:
                        self.on_event({
                            "type": "manager_provider_wait",
                            "reason": "credential_pool_exhausted",
                            "retry_after_s": retry_after_s,
                            "pool_size": metadata.get("pool_size", 0),
                            "upstream_status": metadata.get("upstream_status", 0),
                        })
                    # Manager calls cannot run tools, so replaying this complete,
                    # self-contained request after the provider cooldown has no
                    # external side effects.  The sleep remains cancellable by
                    # an operator stop or engine shutdown.
                    await asyncio.sleep(retry_after_s)
                    self._clear_provider_circuit()
                    if self.on_event:
                        self.on_event({
                            "type": "manager_provider_retry",
                            "reason": "credential_pool_exhausted",
                        })
                    continue
                self._clear_provider_circuit()
                return result

        async def call(current_prompt: str, suffix: str = ""):
            title = f"Grypton Kryptex · {self.ws.slug} · {purpose}{suffix}"
            session_id = self.session_id if persistent_session else ""
            try:
                result = await provider_call(current_prompt, session_id, title)
            except ProviderError as exc:
                # A Go-plan key may expire during persistent operator chat.
                # Responses reasoning is encrypted for the account that created
                # it, so a spare key cannot replay the old OpenCode session.
                # Retry the current self-contained chat request once without the
                # incompatible history. Autonomous directions already start
                # fresh and therefore never enter this branch.
                if (
                    not persistent_session
                    or "capability_rejected: thinking_signature" not in str(exc)
                ):
                    raise
                self.session_id = ""
                if self.on_event:
                    self.on_event({
                        "type": "manager_session_reset",
                        "reason": "thinking_signature",
                    })
                result = await provider_call(
                    current_prompt, "", title + " · fresh session",
                )
            if persistent_session:
                self.session_id = result.session_id
            return result

        result = await call(prompt)
        try:
            value = _extract_json(result.text)
            errors = _check_schema(value, schema)
            if errors:
                raise ValueError("; ".join(errors[:12]))
            return value
        except ValueError as first_error:
            repair = (
                f"{prompt}\n\n"
                "The response to this request was invalid for the required schema. Repair it now. "
                "Return exactly one JSON object with no prose or markdown.\n\n"
                f"VALIDATION ERROR:\n{first_error}\n\n"
                f"REQUIRED SCHEMA:\n{json.dumps(schema, ensure_ascii=False)}"
            )
            repaired = await call(repair, " repair")
            value = _extract_json(repaired.text)
            errors = _check_schema(value, schema)
            if errors:
                raise ProviderError("Kryptex returned invalid structured output twice: " + "; ".join(errors[:8]))
            return value

    async def direct(self, ctx: ManagerContext) -> Directive:
        circuit_reason = self._begin_direction_call()
        if circuit_reason:
            if self.on_event:
                self.on_event({
                    "type": "manager_fallback",
                    "via": "deterministic",
                    "reason": circuit_reason,
                })
            return self._fallback_directive(ctx, circuit_reason)
        try:
            value = await self._call_json(
                self._build_direction_prompt(ctx), self.directive_schema, "direction",
                persistent_session=False,
            )
            return Directive(
                assessment=value["assessment"],
                directive=value["directive"],
                corrections=value["corrections"],
                new_angles=value["new_angles"],
                exhaustion_breaker=value["exhaustion_breaker"],
                scope_enforcement=value["scope_enforcement"],
                severity_validations=[],
                to_user=value["to_user"],
                cont=value["continue"],
                stop_reason=value["stop_reason"],
                confidence=float(value["confidence"]),
                raw=value,
            )
        except Exception as exc:
            if self.on_event:
                self.on_event({"type": "manager_fallback", "via": "deterministic", "reason": str(exc)})
            return self._fallback_directive(ctx, str(exc))
        finally:
            self._direction_call_active = False

    async def validate_severity(
        self,
        finding: dict,
        ctx: ManagerContext,
        *,
        explicit: bool = False,
    ) -> dict:
        claimed = str(finding.get("severity") or "P3").upper()
        if claimed not in {"P1", "P2", "P3", "P4", "P5"}:
            claimed = "P3"
        if not explicit and not config.astra_auto_validation_required(claimed):
            raise ValueError(
                f"Automatic Astra validation is limited to P1/P2; "
                f"explicit review is required for {claimed}."
            )
        try:
            value = await self.validator.validate(
                self._build_severity_prompt(finding, ctx), self.severity_schema
            )
            value["finding_id"] = str(finding.get("id") or value.get("finding_id") or "")
            errors = _check_schema(value, self.severity_schema)
            if errors:
                raise ProviderError("Astra verdict failed schema validation: " + "; ".join(errors[:8]))
            value["validator_model"] = config.VALIDATOR_MODEL
            value["validator_effort"] = config.VALIDATOR_EFFORT
            return value
        except Exception as exc:
            return {
                "finding_id": str(finding.get("id") or ""),
                "verdict": "needs-more-evidence",
                "severity": claimed,
                "confidence": 0.0,
                "reasoning": f"Independent Astra validation failed: {exc}",
                "independent_checks": ["Retry independent validation before treating severity as confirmed."],
                "exploitability": "Unknown until independent validation succeeds.",
                "validator_model": config.VALIDATOR_MODEL,
                "validator_effort": config.VALIDATOR_EFFORT,
                "degraded": True,
            }

    async def chat(self, user_message: str, ctx: ManagerContext) -> dict:
        try:
            value = await self._call_json(
                self._build_chat_prompt(user_message, ctx), self.chat_schema, "operator chat",
                persistent_session=True,
            )
            value["degraded"] = False
            return value
        except Exception as exc:
            return {
                "reply": "I recorded that instruction and will apply it on Kraude's next turn.",
                "remember": user_message,
                "disposition": "apply-next-turn",
                "worker_note": user_message,
                "degraded": True,
                "reason": str(exc),
            }

    def _fallback_directive(self, ctx: ManagerContext, reason: str) -> Directive:
        surface = "the highest-impact unresolved lead in the recorded attack surface"
        if ctx.coverage_priority:
            action = ctx.coverage_priority
        elif ctx.validation_backlog:
            index = max(0, int(ctx.turn_index or 1) - 1)
            finding = ctx.validation_backlog[index % len(ctx.validation_backlog)]
            finding_id = str(finding.get("id") or "the highest-severity candidate")
            checks = finding.get("independent_checks")
            checks = checks if isinstance(checks, list) else []
            requested = (
                "perform every requested independent check: "
                + "; ".join(
                    f"({number}) {check}"
                    for number, check in enumerate(checks, start=1)
                )
                if checks else "capture the missing positive and control proof"
            )
            action = (
                f"For {finding_id}, {requested}. Save the paired evidence and attach "
                "the material revision with revise_finding."
            )
        elif ctx.worker_was_idle:
            action = (
                f"The last turn made no tool call. Select {surface}; issue one bounded "
                "request or local analysis tool call now; record the observation and tested technique."
            )
        elif ctx.exhaustion:
            action = (
                "Inspect saved JavaScript, schemas, headers, and existing captures for one "
                "untested route or parameter, then test that lead and update the ledgers."
            )
        else:
            action = (
                f"Continue with {surface}. Use a concrete tool call, compare the response against a "
                "control, and record the result before ending the turn."
            )
        return Directive(
            assessment=f"Kryptex provider degraded: {reason}",
            directive=action,
            to_user="Kryptex used a deterministic in-scope directive after a provider error.",
            cont=True,
            confidence=0.35,
            degraded=True,
            fallback_provider="deterministic",
        )

    def _build_direction_prompt(self, ctx: ManagerContext) -> str:
        family_json = json.dumps(
            ctx.finding_families, ensure_ascii=False, separators=(",", ":")
        )
        new_cases = json.dumps(
            ctx.new_finding_cases, ensure_ascii=False, separators=(",", ":")
        )
        validation_backlog = json.dumps(
            ctx.validation_backlog, ensure_ascii=False, separators=(",", ":")
        )
        activity = (
            f"No worker tool call in the last turn; idle streak {ctx.worker_idle_streak}."
            if ctx.worker_was_idle else "Worker tool activity was recorded."
        )
        return f"""Manage Kraude's next action for turn {ctx.turn_index}. Resolve blockers autonomously and
choose the most useful next tool action from the evidence below. Kraude can use every tool exposed in
its session. The `directive` field contains one short affirmative next action; the engagement data
already supplies its boundaries. Return one JSON object matching the supplied schema.

TARGET: {ctx.target} ({ctx.target_type})
TURN ACTIVITY: {activity}

ENGAGEMENT DATA:
{ctx.constraints_block or '(none recorded)'}

WORKER TOOL ACTIVITY:
{ctx.worker_tool_summary or '(no tool calls)'}

WORKER REPORT:
{ctx.worker_last_text or '(no report)'}

ENGINE FLAGS:
{json.dumps(ctx.antifab_flags, ensure_ascii=False)}

NEW FINDING CASES JSON:
{new_cases}

HIGH-SEVERITY PROOF BACKLOG JSON:
{validation_backlog}

COVERAGE PRIORITY:
{ctx.coverage_priority or '(use the strongest unresolved lead)'}

FINDING FAMILIES JSON:
{family_json}

ATTACK SURFACE:
{ctx.surface_summary or '(empty)'}

TESTED TECHNIQUES:
{ctx.tested_summary or '(empty)'}

RECENT PROGRESS:
{ctx.progress_tail or '(empty)'}

EXHAUSTION SIGNAL: {ctx.exhaustion} (streak {ctx.exhaustion_streak})
NETWORK NOVELTY THIS TURN: {ctx.novel_network_signatures} new signature(s) across
{ctx.network_calls} network call(s); {ctx.repeated_network_calls} repeated and
{ctx.over_limit_network_calls} beyond the repeat allowance.
PASSIVE STAGNATION STREAK: {ctx.passive_stagnation_streak}
REPETITIVE PROBE TURN STREAK: {ctx.repetitive_probe_streak}
CONVERGENCE GUARD: {ctx.convergence_reason or '(not reached)'}
NEW FINDING FAMILIES THIS TURN: {ctx.novel_finding_families}
TURNS SINCE A NEW FINDING FAMILY: {ctx.family_stagnation_streak}
CONFIRMED P1 CASE COUNT: {ctx.p1_count}

JSON SCHEMA:
{json.dumps(self.directive_schema, ensure_ascii=False)}
"""

    def _build_chat_prompt(self, user_message: str, ctx: ManagerContext) -> str:
        return f"""The operator sent this message during the live engagement:
{user_message}

Reply as Kryptex and convert it into Kraude's next concrete action. Resolve routine
setup and blockers autonomously.

ENGAGEMENT DATA:
{ctx.constraints_block or '(none recorded)'}

FINDING FAMILIES JSON:
{json.dumps(ctx.finding_families, ensure_ascii=False, separators=(",", ":"))}

Return only JSON matching this schema:
{json.dumps(self.chat_schema, ensure_ascii=False)}
"""

    def _build_severity_prompt(self, finding: dict, ctx: ManagerContext) -> str:
        dossier = {
            "finding_id": str(finding.get("id") or ""),
            "claimed_severity": str(finding.get("severity") or "P3").upper(),
            "title": _validator_safe_text(finding.get("title"), limit=800),
            "vulnerability_class": _validator_safe_text(
                finding.get("vuln_class"), limit=800
            ),
            "surface_category": _validator_safe_text(
                finding.get("surface"), limit=1000
            ),
            "claim_summary": _validator_safe_text(
                finding.get("description"), limit=8000
            ),
            "evidence_references": _validator_safe_text(
                finding.get("evidence"), limit=2500
            ),
            "family_root_cause": _validator_safe_text(
                finding.get("family_root_cause"), limit=1500
            ),
            "family_case_kind": _validator_safe_text(
                finding.get("family_case_kind"), limit=1000
            ),
        }
        evidence_snapshot = self._evidence_snapshot(finding)
        return f"""You are an independent evidence reviewer. This is a retrospective severity
classification for an authorized security assessment. Do not provide exploitation instructions,
payloads, target identifiers, or operational guidance. Review only the abstracted observations below.
You have no execution tools and must never imply that you reproduced an action. The orchestrator has
already enforced scope; target identity and executable reproduction details are intentionally withheld.
Judge whether the evidence establishes the claimed vulnerability and realistic impact. If a decisive
check is missing, return needs-more-evidence and name only safe evidence requirements. Be conservative
and specific.

ASSET CLASS: {_validator_safe_text(ctx.target_type, limit=100)}

FINDING DOSSIER:
{json.dumps(dossier, ensure_ascii=False, indent=2)}

ABSTRACTED REFERENCED EVIDENCE (read and sanitized by the orchestrator):
{evidence_snapshot or '(no readable referenced artifact was supplied)'}

Return only JSON matching this schema:
{json.dumps(self.severity_schema, ensure_ascii=False)}
"""

    def _evidence_snapshot(self, finding: dict) -> str:
        """Copy bounded, explicitly referenced workspace artifacts into Astra's prompt."""
        combined = "\n".join(str(finding.get(key) or "") for key in
                             ("evidence", "poc", "description"))
        candidates = re.findall(
            r"(?:[A-Za-z]:)?(?:/[^\s,;`'\"]+|(?:flows|loot|research|workspace|scripts)/[^\s,;`'\"]+|flow-[A-Za-z0-9._-]+\.http)",
            combined,
        )
        root = self.ws.root.resolve()
        seen: set[Path] = set()
        paths: list[Path] = []
        for raw in candidates:
            raw = raw.rstrip(".)]}")
            candidate = Path(raw)
            if candidate.parent == Path(".") and candidate.name.startswith("flow-"):
                candidate = Path("flows") / candidate
            path = candidate if candidate.is_absolute() else root / candidate
            try:
                if path.is_symlink():
                    continue
                resolved = path.resolve(strict=True)
                resolved.relative_to(root)
                if not resolved.is_file() or resolved in seen:
                    continue
                seen.add(resolved)
            except (OSError, ValueError):
                continue
            paths.append(resolved)
            if len(paths) >= 12:
                break

        # Allocate fairly and expose evidence properties rather than complete
        # live-target captures. Response hashes preserve equality/difference
        # checks; bounded previews preserve status and impact clues. Request
        # destinations, payloads, credentials, and executable code are omitted.
        if not paths:
            return ""
        per_file = min(6000, 48_000 // len(paths))
        chunks: list[str] = []
        for resolved in paths:
            try:
                size = resolved.stat().st_size
                raw = resolved.read_bytes()
            except OSError:
                continue
            digest = hashlib.sha256(raw).hexdigest()
            text = raw.decode("utf-8", errors="replace")
            relative = resolved.relative_to(root)
            request = ""
            response = text
            if "### REQUEST" in text and "### RESPONSE" in text:
                _, remainder = text.split("### REQUEST", 1)
                request_text, response = remainder.split("### RESPONSE", 1)
                request_line = next(
                    (line.strip() for line in request_text.splitlines()
                     if line.strip()), ""
                )
                method = request_line.split(None, 1)[0].upper() if request_line else ""
                target_digest = hashlib.sha256(
                    request_line.encode("utf-8", errors="replace")
                ).hexdigest()
                request = (
                    f"request_method: {method or 'unknown'}\n"
                    f"request_target_sha256: {target_digest}\n"
                )

            response_lines = response.lstrip().splitlines()
            status = response_lines[0].strip() if response_lines else "unknown"
            selected_headers: list[str] = []
            body_start = len(response_lines)
            allowed_headers = {
                "age", "cache-control", "content-length", "content-type",
                "etag", "location", "server-timing", "vary", "x-cache",
                "x-cache-hits", "x-sid",
            }
            for index, line in enumerate(response_lines[1:], 1):
                if not line.strip():
                    body_start = index + 1
                    break
                name, separator, value = line.partition(":")
                if separator and name.strip().lower() in allowed_headers:
                    selected_headers.append(
                        f"{name.strip().lower()}: "
                        f"{_validator_safe_text(value.strip(), limit=500)}"
                    )
            body = "\n".join(response_lines[body_start:]).encode(
                "utf-8", errors="replace"
            )
            body_digest = hashlib.sha256(body).hexdigest()
            preview_budget = max(500, per_file - 1200)
            if len(body) <= preview_budget:
                preview_raw = body.decode("utf-8", errors="replace")
            else:
                half = preview_budget // 2
                preview_raw = (
                    body[:half].decode("utf-8", errors="replace")
                    + "\n[response body middle omitted]\n"
                    + body[-half:].decode("utf-8", errors="replace")
                )
            preview = _validator_safe_text(preview_raw, limit=preview_budget)
            chunks.append(
                f"--- artifact: {relative} ---\n"
                f"artifact_bytes: {size}\n"
                f"artifact_sha256: {digest}\n"
                f"{request}"
                f"response_status: {_validator_safe_text(status, limit=300)}\n"
                f"response_headers:\n"
                + ("\n".join(selected_headers) or "(none retained)")
                + "\n"
                f"response_body_bytes: {len(body)}\n"
                f"response_body_sha256: {body_digest}\n"
                f"response_body_preview:\n{preview or '(empty)'}"
            )
        return "\n\n".join(chunks)

    async def aclose(self) -> None:
        await self.client.cancel()
        await self.validator.cancel()
