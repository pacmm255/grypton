"""Deterministic mock worker + manager for offline end-to-end tests (R34).

These implement the exact async interfaces the engine drives (``KraudeWorker`` /
``KryptexManager``) and produce *real* workspace side-effects (surface, findings,
tested techniques), so the full orchestration — delta detection, independent
severity validation, exhaustion→expansion, non-stop override, anti-fabrication —
is exercised without any network or model calls.
"""
from __future__ import annotations

import asyncio
from typing import Callable, Optional

from .manager import Directive, ManagerContext
from .worker import TurnResult


class MockWorker:
    def __init__(self, ws, on_event: Optional[Callable] = None,
                 script: Optional[Callable] = None):
        from types import SimpleNamespace
        from . import config as _cfg
        self.ws = ws
        self.on_event = on_event
        self.script = script or self._default_script
        self.counter = 0
        self.session_id = "mock-session"
        self._started = False
        # mimic KraudeWorker's .spec.model so engine model-swap logic works in tests
        self.spec = SimpleNamespace(model=_cfg.WORKER_MODEL, cwd=ws.root,
                                    session_uuid="mock-session")

    async def start(self):
        self._started = True

    async def ensure_started(self):
        self._started = True

    async def aclose(self):
        self._started = False

    async def rewind_idle_tail(self):
        # Mock has no real session JSONL; track calls for tests.
        self.rewind_calls = getattr(self, "rewind_calls", 0) + 1
        return 1

    async def run_turn(self, directive: str) -> TurnResult:
        await asyncio.sleep(0)  # yield to the loop
        self.counter += 1
        text = self.script(self, directive)
        # emit stream-like events so the full engine/renderer event path runs
        if self.on_event:
            if self.counter == 1:
                self.on_event({"type": "system", "subtype": "init", "model": "mock-glm-5.3",
                               "tools": ["Bash", "Read"], "mcp_servers": [{"name": "grypton"}],
                               "session_id": "mock"})
            self.on_event({"type": "stream_event",
                           "event": {"type": "content_block_delta",
                                     "delta": {"type": "text_delta", "text": text}}})
            self.on_event({"type": "assistant",
                           "message": {"role": "assistant",
                                       "content": [{"type": "tool_use",
                                                    "name": "Bash",
                                                    "input": {"command": "curl -s https://t/api"}}]}})
            self.on_event({"type": "user",
                           "message": {"role": "user",
                                       "content": [{"type": "tool_result",
                                                    "content": [{"type": "text",
                                                                 "text": "HTTP/2 200\n(mock tool output)"}]}]}})
        return TurnResult(assistant_text=text,
                          tool_uses=[{"name": "Bash", "input": {"command": "curl ..."}}],
                          result={"is_error": False, "num_turns": 1, "total_cost_usd": 0.0},
                          num_turns=1, duration_s=0.01)

    @staticmethod
    def _default_script(self, directive: str) -> str:
        d = (directive or "").lower()
        i = self.counter
        if "fabtest" in d:
            return "Wrote results to /root/grypton/.state/engagements/ghost/missing.md (412 lines)."
        if "expansion" in d or "expand the" in d:
            self.ws.append_attack_surface(
                item=f"/api/expanded/{i}", kind="endpoint",
                interesting="discovered via manager-directed expansion")
            return f"Expanded the surface per Kryptex: discovered /api/expanded/{i} and probed it."
        if i == 1:
            self.ws.append_attack_surface(item="/api/v2/login", kind="endpoint")
            self.ws.append_attack_surface(item="/api/v2/users/{id}", kind="endpoint",
                                          interesting="IDOR candidate")
            return "Recon complete: mapped the initial API surface."
        if i == 2:
            self.ws.log_tested_technique(surface="/api/v2/login",
                                         technique="default credential spray", result="blocked")
            self.ws.append_attack_surface(item="POST /graphql", kind="schema",
                                          interesting="introspection appears enabled")
            return "Login resists default creds; found a GraphQL endpoint with introspection."
        if i == 3:
            self.ws.record_finding(
                title="IDOR on /api/v2/users/{id}", severity="P2", vuln_class="IDOR",
                surface="/api/v2/users/{id}",
                description="Sequential user IDs expose other users' PII.",
                poc="GET /api/v2/users/2 returns user 2's profile while authed as user 1.",
                evidence="flows/flow-idor.http")
            return "Confirmed an IDOR (claimed P2)."
        if i == 4:
            self.ws.record_finding(
                title="Auth bypass via JWT alg confusion", severity="P1",
                vuln_class="Authentication bypass", surface="/api/v2/login",
                description="Server accepts HS256 tokens signed with the public RSA key.",
                poc="Forge token with alg=HS256 keyed on the public cert → full account takeover.",
                evidence="flows/flow-jwt.http")
            return "Confirmed a critical authentication bypass (claimed P1)."
        return f"Turn {i}: re-reviewed known surface; nothing new on the current path."


class MockManager:
    def __init__(self, ws, system_prompt: str, on_event: Optional[Callable] = None,
                 stop_on_turn: int = 0, stop_hard: bool = False):
        self.ws = ws
        self.system_prompt = system_prompt
        self.on_event = on_event
        self.session_id = "mock-mgr-session"
        self.stop_on_turn = stop_on_turn
        self.stop_hard = stop_hard

    async def direct(self, ctx: ManagerContext) -> Directive:
        await asyncio.sleep(0)
        validations = []
        for f in ctx.new_findings:
            sev = f.get("severity", "P3")
            validations.append({"finding_id": f.get("id"), "verdict": "confirm",
                                "severity": sev, "confidence": 0.85,
                                "reasoning": "Independently reproduced from the workspace evidence."})
        corrections = []
        if ctx.antifab_flags:
            corrections.append("Retract or prove these unverifiable claims: "
                               + "; ".join(ctx.antifab_flags))
        if self.stop_on_turn and ctx.turn_index >= self.stop_on_turn:
            return Directive(
                assessment="Mock stop requested.",
                directive="(attempting to stop)",
                cont=False,
                stop_reason=("Out-of-scope / authorization boundary reached"
                             if self.stop_hard else "I think we are done"),
            )
        if ctx.exhaustion:
            return Directive(
                assessment="Surface looks stalled; breaking the wall.",
                directive="Introspect the GraphQL schema fully and fuzz mutations for authz gaps.",
                exhaustion_breaker="New angle: dump the GraphQL schema, then test every mutation "
                                   "for missing authorization — a class we have not tried here.",
                severity_validations=validations, corrections=corrections,
                to_user=f"Turn {ctx.turn_index}: stalled — directing a fresh GraphQL authz angle.",
                cont=True, confidence=0.7)
        return Directive(
            assessment=f"Reviewed turn {ctx.turn_index}.",
            directive="Probe the most promising untested surface item with real requests; "
                      "diff authenticated vs unauthenticated responses.",
            severity_validations=validations, corrections=corrections,
            new_angles=["Check the GraphQL introspection result for hidden mutations."],
            to_user=f"Turn {ctx.turn_index}: {len(ctx.new_findings)} new finding(s); directing next probe.",
            cont=True, confidence=0.8)

    async def validate_severity(self, finding: dict, ctx: ManagerContext) -> dict:
        await asyncio.sleep(0)
        return {"finding_id": finding.get("id"), "verdict": "confirm",
                "severity": finding.get("severity", "P3"), "confidence": 0.85,
                "reasoning": "Independently reproduced."}

    async def chat(self, user_message: str, ctx: ManagerContext) -> dict:
        await asyncio.sleep(0)
        return {"reply": f"Understood: '{user_message}'. I'll fold it into Kraude's next move.",
                "remember": user_message, "disposition": "apply-next-turn",
                "worker_note": user_message, "degraded": False}

    def _fallback_directive(self, ctx, reason):
        return Directive(directive="Continue; expand if blocked.", cont=True, degraded=True)
