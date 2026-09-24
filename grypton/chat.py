"""Grypton's live terminal: worker tools, manager direction, and validation.

You talk to **Kryptex** (the manager) by default; `/worker <msg>` talks to **Kraude**
directly. Kryptex replies to your messages in REAL TIME (concurrent with whatever
Kraude is doing) and remembers them. The console exposes system init, Kraude's
stream, tool activity, directives, findings, and severity verdicts. Operators can
switch between quiet, normal, and full views without changing durable evidence.
"""
from __future__ import annotations

import asyncio
import json
import re
import shlex
import shutil
import subprocess
import sys
import textwrap
import time
from pathlib import Path

from .finding_views import (
    confirmed_finding_cases,
    confirmed_p1_cases,
    finding_case_rows,
    finding_case_verdict,
    finding_family_counts,
    finding_family_for_case,
    finding_family_view,
    safe_display_text,
    terminal_family_lines,
)

# Natural-language stop intent: a message made up ONLY of stop words + filler
# (e.g. "ok enough you can stop now") halts the engine. A nuanced message like
# "stop testing CORS but keep going" is NOT a stop — it routes to Kryptex.
_STOP_WORDS = {"stop", "halt", "abort", "quit", "cease", "terminate", "enough", "kill", "end", "wrap"}
_STOP_FILLER = {"ok", "okay", "you", "youre", "can", "could", "it", "now", "please", "the",
              "this", "that", "thats", "grypton", "kryptex", "everything", "all", "hunt",
                "engagement", "pls", "just", "we", "were", "are", "is", "good", "its", "yeah",
                "yep", "yes", "for", "today", "right", "alright", "hey", "so", "done", "finish",
                "no", "more", "lets", "up", "and", "i", "im", "think", "fine", "to",
                "want", "anymore", "session", "run", "thanks", "thank"}


def _is_stop_intent(text: str) -> bool:
    # strip apostrophes so contractions normalise ("that's"->"thats", "we're"->"were")
    toks = re.findall(r"[a-z]+", text.lower().replace("'", ""))
    return bool(toks) and any(t in _STOP_WORDS for t in toks) and \
        all(t in _STOP_WORDS or t in _STOP_FILLER for t in toks)


# Strip stray terminal control sequences from user input (arrow keys, function
# keys, color codes). Canonical mode passes these through as raw bytes if the
# terminal doesn't have proper line editing — without this they get submitted
# as garbage messages and pollute standing_instructions.
_ANSI_CTRL_RX = re.compile(
    r"\x1b\[[0-9;?]*[a-zA-Z~]"          # CSI sequences (arrows, function keys, colors)
    r"|\x1b[NOP=>]"                      # SS2/SS3/keypad
    r"|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]" # other C0 controls (keep \t \n \r)
)

# Terminal output is often copied to tickets or screen-shared. Captures remain
# complete in the private workspace, while the operator console removes common
# credential forms from streamed output and command previews.
_DISPLAY_SECRET_RX = re.compile(
    r'(?i)(\b(?:password|passwd|secret|token|api[_-]?key|hmac[_ -]?key|authorization|cookie)\b'
    r'\s*[:=]\s*)([^\s,;&}\]\)]+)'
)
_DISPLAY_JSON_SECRET_RX = re.compile(
    r'(?i)("(?:password|passwd|secret|token|api[_-]?key|hmac[_-]?key|authorization|cookie)"\s*:\s*")'
    r'([^"\\]*(?:\\.[^"\\]*)*)(")'
)
_DISPLAY_BEARER_RX = re.compile(r'(?i)(\bbearer\s+)[\w.\-+/=]+')


def _redact_display(text: object) -> str:
    value = str(text or "")
    value = _DISPLAY_JSON_SECRET_RX.sub(r'\1[REDACTED]\3', value)
    value = _DISPLAY_SECRET_RX.sub(r'\1[REDACTED]', value)
    return _DISPLAY_BEARER_RX.sub(r'\1[REDACTED]', value)


def _sanitize_input(text: str) -> str:
    return _ANSI_CTRL_RX.sub("", text)


_TTY = sys.stdout.isatty()
_WIDTH = min(shutil.get_terminal_size((100, 40)).columns, 118)


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _TTY else s


def cyan(s): return _c("36", s)
def green(s): return _c("32", s)
def bgreen(s): return _c("1;32", s)
def magenta(s): return _c("35", s)
def bmagenta(s): return _c("1;35", s)
def yellow(s): return _c("33", s)
def red(s): return _c("31", s)
def blue(s): return _c("34", s)
def dim(s): return _c("2", s)
def bold(s): return _c("1", s)


def _wrap(text: str, indent: str = "    ", width: int = None) -> str:
    width = width or _WIDTH
    out = []
    for para in (text or "").splitlines() or [""]:
        if not para.strip():
            out.append("")
        else:
            out.append(textwrap.fill(para, width=width, initial_indent=indent,
                                     subsequent_indent=indent,
                                     replace_whitespace=False, break_long_words=False))
    return "\n".join(out)


def _block(text: str, *, border: str = "┃ ", maxlen: int = 1800, maxlines: int = 50) -> str:
    """Render a code/output block with a dim left border, truncated."""
    text = (text or "").rstrip("\n")
    extra = ""
    if len(text) > maxlen:
        extra = f"… [+{len(text) - maxlen} more chars]"
        text = text[:maxlen]
    lines = text.split("\n")
    if len(lines) > maxlines:
        extra = f"… [+{len(lines) - maxlines} more lines]"
        lines = lines[:maxlines]
    rendered = "\n".join(dim("  " + border) + ln for ln in lines)
    if extra:
        rendered += "\n" + dim("  " + border + extra)
    return rendered


def _render_tool(name: str, inp):
    """Return (headline, body-or-None) for a tool call, formatted per tool."""
    name = name or "tool"
    inp = inp if isinstance(inp, dict) else {}
    disp = name.replace("mcp__grypton__", "grypton.").replace("mcp__krypton__", "grypton.").replace("mcp__", "")
    head = yellow(f"  ⏺ {disp}")
    body = None
    if name == "Bash" and "command" in inp:
        desc = inp.get("description", "")
        if desc:
            head += dim(f"  — {desc}")
        body = "$ " + _redact_display(inp["command"])
    elif name == "Write" and "file_path" in inp:
        head += "  " + str(inp["file_path"])
        body = _redact_display(inp.get("content", ""))
    elif name == "Edit" and "file_path" in inp:
        head += "  " + str(inp["file_path"])
        body = _redact_display(f"- {inp.get('old_string', '')}\n+ {inp.get('new_string', '')}")
    elif name in ("Read", "NotebookEdit") and "file_path" in inp:
        head += "  " + str(inp["file_path"])
    elif name in ("WebFetch", "WebSearch"):
        head += "  " + str(inp.get("url") or inp.get("query", ""))
    elif inp:
        body = _redact_display(json.dumps(inp, ensure_ascii=False))
    return head, body


def _tool_error_summary(content: str) -> str | None:
    """Turn verbose provider permission dumps into an actionable console line."""
    value = str(content or "")
    lowered = value.lower()
    if "external_directory" in lowered and "prevents you from using" in lowered:
        return "OpenCode blocked a local path outside the engagement binding."
    if "permission" in lowered and "denied" in lowered and len(value) > 500:
        return "OpenCode denied this tool call; use the scoped Grypton tool for the action."
    return None


def _compact_tool_result(content: str) -> str:
    """Keep normal view legible while durable logs retain full MCP payloads."""
    try:
        value = json.loads(content)
    except (TypeError, ValueError):
        return str(content or "")
    if not isinstance(value, dict):
        return str(content or "")
    summary = str(value.get("summary") or "").strip()
    if not summary:
        return str(content or "")
    data = value.get("data") if isinstance(value.get("data"), dict) else {}
    lines = [summary]
    # The worker already receives the document body.  Reprinting it in the
    # terminal turns a one-line read into an unreadable JSON wall.
    if "text" in data:
        return summary
    if data.get("status_line"):
        lines.append(str(data["status_line"]))
    flow = data.get("flow")
    if isinstance(flow, str) and flow:
        lines.append(f"capture: {Path(flow).name}")
    record = data.get("id")
    if record:
        lines.append(f"record: {record}")
    return "\n".join(lines)


class Renderer:
    """Engine event sink → terminal. Shows everything, colored."""

    def __init__(self, view: str = "normal"):
        self._turn = 0
        self._line_open = False     # a streamed line is awaiting its newline
        self._stream_mode = None    # None | 'text' | 'thinking'
        self._streamed_text = False  # did final text stream this turn?
        # Evidence is always retained in the workspace. This only controls how
        # much of the live stream reaches the terminal.
        self.view = "normal"        # quiet | normal | full
        self.set_view(view)

    def set_view(self, view: str) -> bool:
        value = (view or "").strip().lower()
        if value not in {"quiet", "normal", "full"}:
            return False
        self.view = value
        return True

    def emit(self, kind: str, **d) -> None:
        try:
            self._emit(kind, **d)
        except Exception:
            pass

    def _break_line(self) -> None:
        if self._line_open:
            print()
            self._line_open = False
        self._stream_mode = None

    def _stream(self, mode: str, header: str, text: str, dimmed: bool = False) -> None:
        if self._stream_mode != mode:
            if self._line_open:
                print()
            print(header)
            self._stream_mode = mode
            self._line_open = False
        sys.stdout.write(dim(text) if dimmed else text)
        sys.stdout.flush()
        self._line_open = True

    def _emit(self, kind, **d):
        if kind not in ("worker_delta", "worker_thinking"):
            self._break_line()

        if kind == "status":
            print(cyan(f"◆ {d.get('text','')}"))

        elif kind == "turn":
            self._turn = d.get("index", self._turn + 1)
            self._stream_mode = None
            self._streamed_text = False
            print()
            print(dim("─" * _WIDTH))
            print(bold(f"✦ Turn {self._turn}") + dim("  Kraude is working…"))

        elif kind == "heartbeat":
            print(dim(f"  · Kraude is working — {d.get('elapsed', 0)}s, "
                      f"{d.get('tools', 0)} tool call(s) so far"))

        elif kind == "worker_system":
            mcp = ", ".join(d.get("mcp") or []) or "—"
            print(blue(f"  ◈ session online — model={d.get('model','?')} "
                       f"tools={d.get('tools','?')} mcp=[{mcp}]"))

        elif kind == "worker_thinking":
            if self.view != "quiet":
                self._stream("thinking", dim("  · Kraude reasoning"), d.get("text", ""), dimmed=True)

        elif kind == "worker_delta":
            self._stream("text", green("  ✦ Kraude"), d.get("text", ""))
            self._streamed_text = True

        elif kind == "worker_tool":
            head, body = _render_tool(d.get("name"), d.get("input"))
            print(head)
            if body:
                print(_block(body))

        elif kind == "worker_tool_result":
            content = _redact_display(d.get("content", ""))
            label = red("  ⎿ error") if d.get("is_error") else dim("  ⎿ result")
            print(label)
            summary = _tool_error_summary(content) if d.get("is_error") else None
            if summary:
                print(_wrap(summary, "      "))
                return
            if self.view == "quiet":
                first = next((line.strip() for line in str(content).splitlines() if line.strip()),
                             "(empty result)")
                print(_wrap(first[:360] + (" …" if len(first) > 360 else ""), "      "))
            elif self.view == "full":
                print(_block(content, maxlen=3600, maxlines=100))
            else:
                print(_block(_compact_tool_result(content), maxlen=1000, maxlines=10))

        elif kind == "worker_turn":
            txt = (d.get("text") or "").strip()
            if txt and not self._streamed_text:
                print(green("  ✦ Kraude"))
                print(_wrap(txt))
            meta = []
            if d.get("cost"):
                meta.append(f"${d['cost']:.4f}")
            if d.get("dur"):
                meta.append(f"{d['dur']:.0f}s")
            if d.get("tools"):
                meta.append(f"{len(d['tools'])} tool call(s)")
            if meta:
                print(dim("    " + " · ".join(meta)))

        elif kind == "codex":
            knd = d.get("kind", "")
            txt = (d.get("text") or "").strip()
            if not txt:
                return
            if knd == "command":
                parts = txt.split("\n→ ", 1)
                print(magenta("  · Kryptex runs: ") + dim(parts[0][:200]))
                if len(parts) > 1:
                    print(_block(parts[1], maxlen=400, maxlines=8))
            elif knd == "error":
                print(red(f"  · Kryptex (codex) error: {txt[:200]}"))
            else:  # reasoning
                print(dim(f"  · Kryptex reasoning: {txt[:300]}"))

        elif kind == "manager":
            if d.get("degraded"):
                print(yellow("  ⚠ Kryptex degraded — Kraude continuing autonomously"))
            fp = d.get("fallback_provider", "")
            header = "  ✦ Kryptex"
            if fp:
                header = f"  ✦ Kryptex ({fp} fallback)"
            print(bmagenta(header))
            if d.get("assessment"):
                print(magenta("    assessment:"))
                print(_wrap(d["assessment"], "      "))
            if d.get("corrections"):
                print(red("    ✎ corrections:"))
                for c in d["corrections"]:
                    print(_wrap(f"• {c}", "      "))
            if d.get("directive"):
                print(magenta("    → directive to Kraude:"))
                print(_wrap(d["directive"], "      "))
            if d.get("new_angles"):
                print(magenta("    ✦ new angles:"))
                for a in d["new_angles"]:
                    print(_wrap(f"• {a}", "      "))
            if d.get("to_user"):
                print(yellow(f"  ⎿ {d['to_user']}"))

        elif kind == "kryptex_chat":
            print()
            print(bmagenta("  ✦ Kryptex"))
            print(_wrap(d.get("reply", ""), "      "))
            if d.get("remember"):
                print(dim(f"      ⟲ remembered: {d['remember']}"))
            if d.get("disposition"):
                print(dim(f"      → disposition: {d['disposition']}"))
            print()

        elif kind == "finding":
            f = d.get("finding", {})
            print(bgreen(f"  ✦ FINDING {f.get('id','')}: {f.get('title','')} "
                         f"[claimed {f.get('severity','?')}] ({f.get('status','')})"))

        elif kind == "validation_start":
            print(blue(f"  ⚖ Astra validation started for {d.get('finding_id','')} "
                       f"({d.get('model','')} · {d.get('effort','')})"))

        elif kind == "validation_complete":
            v = d.get("verdict", {})
            print(blue(f"  ⚖ Astra returned {v.get('verdict','?')} / "
                       f"{v.get('severity','?')} for {d.get('finding_id','')}"))

        elif kind == "verdict":
            v = d.get("verdict", {})
            print(blue(f"  ⚖ Astra verdict on {d.get('finding_id','')}: "
                       f"{v.get('verdict','?')} → {v.get('severity','?')} "
                       f"(conf {v.get('confidence','?')})"))
            if v.get("reasoning"):
                print(_wrap(v["reasoning"], "      "))

        elif kind == "antifab":
            print(red("  ⚠ anti-fabrication flags (Kryptex will confront):"))
            for fl in d.get("flags", []):
                print(_wrap(f"• {fl}", "      "))

        elif kind == "idle":
            n = d.get("streak", 1)
            print(red(f"  ⛔ Kraude was IDLE (0 tool calls) — Kryptex will reframe + force "
                      f"action{' (streak ' + str(n) + ')' if n > 1 else ''}"))

        elif kind == "manager_fallback":
            print(yellow("  ⤴ Kryptex provider failed — deterministic in-scope direction is active."))
            if d.get("reason"):
                print(dim(f"      reason: {d['reason'][:240]}"))

        elif kind == "gateway":
            event = d.get("event") if isinstance(d.get("event"), dict) else {}
            event_type = event.get("type")
            if event_type == "openclaude_notice":
                print(yellow(f"  ↻ OpenClaude · {d.get('role', 'role')}: "
                             f"{event.get('message', '')}"))
            elif event_type == "openclaude_effort" and self.view != "quiet":
                print(dim(f"  · OpenClaude effort · {d.get('role', 'role')} · "
                          f"{event.get('requested', 'auto')} → "
                          f"{event.get('effective', 'auto')} ({event.get('status', '')})"))
            elif event_type == "openclaude_gateway" and self.view == "full":
                print(dim(f"  · OpenClaude gateway · {d.get('role', 'role')} · "
                          f"{event.get('route', '')} · {event.get('effort', '')}"))
            elif event_type == "openclaude_request" and self.view == "full":
                print(dim(f"  · OpenClaude request · {d.get('role', 'role')} · "
                          f"{event.get('route', '')} · tools={len(event.get('tools') or [])}"))

        elif kind == "model_switch":
            print(green(f"◆ {d.get('role', 'role').title()} now uses "
                        f"{d.get('route', '')} · {d.get('effort', '')} via OpenClaude."))

        elif kind == "error":
            print(red(f"  ✖ {d.get('text','')}"))

        elif kind == "user_echo":
            target_name = "Kraude (next turn)" if d.get("to_worker") else "Kryptex (real-time)"
            text = (d.get("text") or "")
            lines = text.split("\n")
            print(cyan(f"  ↳ you → {target_name}: ") + lines[0])
            for ln in lines[1:]:
                print(cyan("      ") + ln)


HELP = """\
Grypton Code commands

  <text>                 send a message to Kryptex
  @document              attach a current-workspace document to the message
  !command               run a read-only local inspection command

  /help                  show this command list
  /clear                 clear the terminal
  /compact               switch to the compact console view
  /context               show current context and workspace coverage
  /cost                  show recorded worker-turn cost and provider calls
  /config                show model routes, scope mode, and console configuration
  /status                show current run status
  /resume                show the persistent engagement identifier to resume later
  /permissions           show enforced tool and network boundaries

  /summary               compact operator decision view
  /plan                  show Kryptex's next directive
  /activity [N]          recent audited tool calls (default 8)
  /flows [N]             recent capture IDs and sizes (default 8)
  /history [N]           recent worker-turn summaries (default 5)
  /findings [N]          finding families and evidence cases (default 20)
  /surface               attack-surface ledger
  /tested                tested-techniques ledger
  /scope                 binding scope and standing instructions
  /models [filter]       browse available OpenClaude routes
  /model                  show active routes
  /model kraude ROUTE [EFFORT]
  /model kryptex ROUTE [EFFORT]
  /audit                 evidence, scope, and validator integrity check
  /view quiet|normal|full control stream detail
  /note <text>           persist an operator note without a manager call
  /worker <text>         send a direct next-turn instruction to Kraude
  /stop                  request a clean stop after the active worker step
"""


def _tail_lines(path: Path, limit: int) -> list[str]:
    """Read a bounded tail without forcing the live console to load big ledgers."""
    try:
        with path.open(encoding="utf-8", errors="replace") as stream:
            rows = [line.rstrip("\n") for line in stream if line.strip()]
    except OSError:
        return []
    return rows[-max(1, min(limit, 50)):]


def _command_limit(argument: str, default: int) -> int:
    text = (argument or "").strip()
    if not text:
        return default
    try:
        value = int(text)
    except ValueError:
        raise ValueError("expected a whole-number limit") from None
    if not 1 <= value <= 50:
        raise ValueError("limit must be between 1 and 50")
    return value


def _print_status(engine, renderer: Renderer) -> None:
    meta = engine.ws.load_meta()
    elapsed = int(time.time() - engine._start_time) if engine._start_time else 0
    findings = finding_case_rows(engine.ws)
    families, _family_errors = finding_family_view(engine.ws)
    family_count, case_count = finding_family_counts(families)
    print(cyan(
        f"◆ status={meta.status} · turn={engine.turn_index} · elapsed={elapsed // 60}m{elapsed % 60:02d}s "
        f"· families={family_count} · cases={case_count} · surface={len(engine.ws.surface.all())} "
        f"· confirmed-P1-cases={len(confirmed_p1_cases(findings))} · stream={renderer.view}"
    ))


def _print_summary(engine, renderer: Renderer) -> None:
    """A decision-oriented snapshot intended for use while a turn is running."""
    meta = engine.ws.load_meta()
    constraints = engine.ws.load_constraints()
    findings = finding_case_rows(engine.ws)
    confirmed = confirmed_finding_cases(findings)
    families, _family_errors = finding_family_view(engine.ws)
    family_count, case_count = finding_family_counts(families)
    latest = findings[-1] if findings else {}
    print(bold(cyan("\n╭─ Grypton live summary")))
    print(f"│ target      {meta.target} ({meta.target_type}) · {meta.status} · turn {engine.turn_index}")
    print(f"│ coverage    surface={len(engine.ws.surface.all())} · tested={len(engine.ws.tested.all())} "
          f"· families={family_count} · cases={case_count} · confirmed-cases={len(confirmed)}")
    print(f"│ scope       {', '.join(constraints.in_scope) or '—'}")
    if latest:
        verdict = finding_case_verdict(latest)
        state = verdict.get("verdict") or latest.get("status", "recorded")
        severity = verdict.get("severity") or latest.get("severity", "?")
        family_id = finding_family_for_case(families, latest.get("id"))
        title = safe_display_text(_redact_display(latest.get("title", "")), 110)
        print(f"│ latest      {latest.get('id', '?')} (family {family_id}) · "
              f"{severity} · {state} · {title}")
    else:
        print("│ latest      no finding recorded")
    directive = _redact_display((meta.last_directive or "").strip().replace("\n", " "))
    print(f"│ next        {directive[:220] or 'Kryptex is preparing the next directive.'}")
    print(f"│ stream      {renderer.view} · `/activity`, `/flows`, and `/plan` provide detail")
    print(bold(cyan("╰────────────────────────────────────────────────────────────────")))


def _print_activity(engine, limit: int) -> None:
    rows = _tail_lines(engine.ws.root / ".ledger" / "tool-calls.jsonl", limit)
    if not rows:
        print(dim("No audited tool calls yet."))
        return
    print(bold("Recent audited tool activity:"))
    for raw in rows:
        try:
            row = json.loads(raw)
        except ValueError:
            continue
        marker = green("✓") if row.get("ok") else red("!")
        tool = str(row.get("tool") or "tool")
        summary = " ".join(_redact_display(row.get("summary")).split())
        print(f"  {marker} {tool:<24} {summary[:180]}")


def _print_flows(engine, limit: int) -> None:
    try:
        rows = sorted(engine.ws.flows_dir.glob("flow-*.http"),
                      key=lambda path: path.stat().st_mtime, reverse=True)[:limit]
    except OSError:
        rows = []
    if not rows:
        print(dim("No captured flows yet."))
        return
    print(bold("Recent private captures:"))
    for path in rows:
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        print(f"  {path.stem:<34} {size:>8} bytes")
    print(dim("  Use `grypton tools --target TARGET flow-read FLOW_ID` for an explicit capture review."))


def _print_history(engine, limit: int) -> None:
    rows = _tail_lines(engine.ws.transcripts_dir / "turns.jsonl", limit)
    if not rows:
        print(dim("No completed worker turns yet."))
        return
    print(bold("Recent Kraude turns:"))
    for raw in rows:
        try:
            row = json.loads(raw)
        except ValueError:
            continue
        summary = " ".join(_redact_display(row.get("assistant_text")).strip().split())
        print(f"  turn {row.get('turn', '?'):>3} · tools={len(row.get('tools') or [])} · "
              f"{summary[-190:] or '(no text summary)'}")


def _print_audit(engine) -> None:
    from .reporting import audit_workspace
    result = audit_workspace(engine.ws)
    counts = result.get("counts", {})
    state = green("PASS") if result.get("ok") else yellow("ATTENTION")
    print(f"Grypton audit: {state} · tools={counts.get('tool_calls', 0)} · "
          f"flows={counts.get('flows', 0)} · scope violations={len(result.get('scope_violations', []))} · "
          f"required validation gaps={len(result.get('unvalidated_findings', []))} · "
          f"family integrity errors={len(result.get('finding_family_integrity_errors', []))}")


def _print_context(engine) -> None:
    """Claude Code-style context view, grounded in Grypton's durable state."""
    docs = ("findings.md", "attack-surface.md", "tested-techniques.md", "progress.md", "scope-rules.md")
    sizes = {}
    for name in docs:
        try:
            sizes[name] = (engine.ws.root / name).stat().st_size
        except OSError:
            sizes[name] = 0
    families, _family_errors = finding_family_view(engine.ws)
    family_count, case_count = finding_family_counts(families)
    print(bold("Context"))
    print(f"  engagement  {engine.ws.slug} · turn {engine.turn_index} · workspace {engine.ws.root}")
    print(f"  records     surface={len(engine.ws.surface.all())} · tested={len(engine.ws.tested.all())} · "
          f"finding-families={family_count} · cases={case_count}")
    print("  documents   " + " · ".join(f"{name.removesuffix('.md')}={size // 1024}k"
                                       for name, size in sizes.items()))
    print(dim("  Durable ledgers are supplied to the roles each turn; `/compact` changes terminal detail only."))


def _print_findings(engine, limit: int) -> None:
    families, errors = finding_family_view(engine.ws)
    family_count, case_count = finding_family_counts(families)
    if errors:
        print(yellow(
            f"Family catalog integrity has {len(errors)} error(s); "
            "showing safe singleton cases."
        ))
    if not case_count:
        print(dim(
            "No valid finding cases can be displayed."
            if errors else "No findings recorded."
        ))
        return
    print(bold(f"Finding families: {family_count} · evidence cases: {case_count}"))
    for line in terminal_family_lines(families, limit=limit):
        print(line)


def _print_cost(engine) -> None:
    total = 0.0
    turns = 0
    for raw in _tail_lines(engine.ws.transcripts_dir / "turns.jsonl", 50):
        try:
            row = json.loads(raw)
        except ValueError:
            continue
        turns += 1
        try:
            total += float(row.get("cost_usd") or 0.0)
        except (TypeError, ValueError):
            pass
    provider_calls = {"Kraude": 0, "Kryptex": 0, "Astra": 0}
    for raw in _tail_lines(engine.ws.transcripts_dir / "provider-calls.jsonl", 100):
        try:
            role = json.loads(raw).get("role")
        except ValueError:
            continue
        label = {"worker": "Kraude", "manager": "Kryptex", "validator": "Astra"}.get(role)
        if label:
            provider_calls[label] += 1
    print(f"Cost · recorded worker turns={turns} · worker cost=${total:.4f}")
    print("Provider calls · " + " · ".join(f"{name}={count}" for name, count in provider_calls.items()))
    print(dim("Manager and validator connectors do not expose a normalized cost field in the local ledger."))


def _print_config(engine, renderer: Renderer) -> None:
    constraints = engine.ws.load_constraints()
    models = engine.current_models()
    print(bold("Configuration"))
    print(f"  worker       {models['kraude']['route']} · {models['kraude']['effort']} · OpenClaude")
    print(f"  manager      {models['kryptex']['route']} · {models['kryptex']['effort']} · OpenClaude")
    print(f"  validator    {models['validator']['route']} · {models['validator']['effort']} (automatic P1/P2)")
    print(f"  console      {renderer.view} · native + Grypton MCP tools")
    print(f"  in scope     {', '.join(constraints.in_scope) or '—'}")


async def _print_model_catalog(search: str = "") -> None:
    from .openclaude import list_models

    try:
        rows = await asyncio.to_thread(list_models, search)
    except Exception as exc:
        print(yellow(f"OpenClaude catalog unavailable: {exc}"))
        return
    available = [row for row in rows if row.status == "available"]
    if not available:
        print(dim("No available OpenClaude models match that filter."))
        return
    print(bold(f"OpenClaude models ({len(available)} available"
               + (f", filter={search!r}" if search else "") + "):"))
    for row in available[:40]:
        efforts = ",".join(row.efforts) or "auto"
        tool = "tools" if row.tools else "text"
        print(f"  {row.route_id:<48} {row.protocol:<10} {tool:<5} {efforts}")
    if len(available) > 40:
        print(dim(f"  … {len(available) - 40} more; use /models FILTER to narrow the list."))


def _print_permissions(engine) -> None:
    constraints = engine.ws.load_constraints()
    print(bold("Permission mode: native + scoped Grypton MCP tools"))
    print(f"  network scope   {', '.join(constraints.in_scope) or '—'}")
    print(f"  exclusions      {', '.join(constraints.out_of_scope) or 'none recorded'}")
    print("  native read/search/edit/task calls can access the public engagement workspace and are retained in provider events.")
    print("  native Bash cannot open network sockets; its curl command uses the scoped Grypton capture broker.")
    print("  native web fetch/search are disabled; Grypton MCP network calls enforce scope and write captures and audit rows.")
    print("  OpenCode questions are disabled; Kryptex resolves ordinary blockers.")
    print("  `!` accepts only read-only local inspection commands; it cannot make network calls.")


_WORKSPACE_REFERENCES = {
    "findings": "findings.md", "findings.md": "findings.md",
    "surface": "attack-surface.md", "attack-surface.md": "attack-surface.md",
    "tested": "tested-techniques.md", "tested-techniques.md": "tested-techniques.md",
    "progress": "progress.md", "progress.md": "progress.md",
    "scope": "scope-rules.md", "scope-rules.md": "scope-rules.md",
}
_WORKSPACE_REFERENCE_RX = re.compile(r"(?<![\w.])@([A-Za-z][A-Za-z0-9._-]*)")


def _expand_workspace_references(engine, text: str) -> str:
    """Resolve Claude-style @mentions to safe, known engagement documents.

    The roles already receive bounded workspace context.  The marker tells them
    exactly which durable document the operator intended to prioritize without
    echoing a document body into the terminal or allowing arbitrary filesystem
    access.
    """
    names = _WORKSPACE_REFERENCE_RX.findall(text)
    if not names:
        return text
    resolved = []
    unknown = []
    for name in names:
        document = _WORKSPACE_REFERENCES.get(name.lower())
        if document:
            resolved.append(document)
        else:
            unknown.append(name)
    if unknown:
        allowed = ", ".join(sorted(set(_WORKSPACE_REFERENCES.values())))
        raise ValueError(f"unknown @ reference: {', '.join(unknown)} (use {allowed})")
    return text + "\n\n[OPERATOR PRIORITY REFERENCES: " + ", ".join(dict.fromkeys(resolved)) + "]"


def _run_local_inspection(engine, command: str) -> None:
    """Support a useful, constrained subset of Claude Code's ! command."""
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        print(yellow(f"Could not parse local command: {exc}"))
        return
    if not parts:
        print(yellow("Usage: !pwd, !ls [workspace-path], !git status, or !python --version"))
        return
    allowed = False
    invocation: list[str] = []
    if parts == ["pwd"]:
        allowed, invocation = True, ["pwd"]
    elif parts and parts[0] == "ls":
        candidate = parts[1:] or ["."]
        if all(not value.startswith("-") for value in candidate):
            try:
                root = engine.ws.root.resolve()
                paths = [(root / value).resolve() for value in candidate]
                if all(path.is_relative_to(root) for path in paths):
                    allowed, invocation = True, ["ls", "-la", *map(str, paths)]
            except OSError:
                pass
    elif parts in (["git", "status"], ["git", "status", "--short"],
                   ["git", "diff", "--stat"]):
        allowed, invocation = True, parts
    elif parts in (["python", "--version"], ["python3", "--version"]):
        allowed, invocation = True, parts
    if not allowed:
        print(yellow("`!` permits only read-only local inspection: pwd, ls [workspace path], "
                     "git status, git diff --stat, or python --version."))
        return
    try:
        completed = subprocess.run(invocation, cwd=engine.ws.root, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        print(red(f"Local inspection failed: {exc}"))
        return
    print(dim(f"$ {' '.join(shlex.quote(value) for value in invocation)}"))
    print(_block(_redact_display(completed.stdout or "(no output)"), maxlen=1800, maxlines=40))


def print_console_header(*, target: str, target_type: str, backend: str,
                         renderer: Renderer, models: dict | None = None) -> None:
    """Render the stable shell before providers begin emitting live events."""
    from . import config
    models = models or {
        "kraude": {"route": config.CONFIG.worker_model, "effort": config.CONFIG.worker_effort},
        "kryptex": {"route": config.CONFIG.manager_model, "effort": config.CONFIG.manager_effort},
        "validator": {"route": config.VALIDATOR_MODEL, "effort": config.VALIDATOR_EFFORT},
    }

    print(bold(cyan("\n╭── Grypton Code ─────────────────────────────────────────────")))
    print(f"│ {target} · {target_type} · {backend}")
    print(dim(f"│ Kraude {models['kraude']['route']} · {models['kraude']['effort']}"))
    print(dim(f"│ Kryptex {models['kryptex']['route']} · {models['kryptex']['effort']}"))
    print(dim(f"│ Astra {models['validator']['route']} · {models['validator']['effort']} · "
              f"console {renderer.view}"))
    print(dim("╰── Type /help for commands · @findings to prioritize a workspace record"))


async def interact(engine, renderer: Renderer | None = None, *, accept_input: bool = True,
                   show_header: bool = True) -> None:
    if renderer is None:
        candidate = getattr(engine.emit, "__self__", None)
        renderer = candidate if isinstance(candidate, Renderer) else Renderer()
    if show_header:
        print_console_header(target=engine.target, target_type=engine.target_type,
                             backend=engine.backend, renderer=renderer,
                             models=engine.current_models())
    loop_task = asyncio.create_task(engine.run())
    if not accept_input:
        await loop_task
        return
    input_task = asyncio.create_task(_input_loop(engine, renderer))
    try:
        done, _ = await asyncio.wait({loop_task, input_task}, return_when=asyncio.FIRST_COMPLETED)
        if loop_task in done:
            input_task.cancel()
        await loop_task
    finally:
        for t in (loop_task, input_task):
            if not t.done():
                t.cancel()
        await asyncio.gather(loop_task, input_task, return_exceptions=True)


# Bracketed-paste markers (DEC mode 2004). Modern terminals (iTerm2, gnome-
# terminal, xterm, alacritty, kitty, vscode, Windows Terminal) wrap pasted text
# in these so we can accumulate the paste as ONE message instead of treating each
# \n as a separate submit.
_PASTE_START = "\x1b[200~"
_PASTE_END = "\x1b[201~"


def _route_input(engine, renderer: Renderer, text: str) -> bool:
    """Process one complete user message; return True if the input loop should exit."""
    text = _sanitize_input(text).strip()
    if not text:
        return False
    if text in ("/quit", "/exit", "/stop"):
        engine.request_stop("user requested stop via chat")
        print(cyan("◆ Stop requested — finishing the current turn, then halting."))
        return True
    if text == "/help":
        print(HELP)
        return False
    if text == "/compact":
        renderer.set_view("quiet")
        engine.ws.append_progress("Operator selected compact terminal view.")
        print(green("✦ Console compacted. Durable workspace context is unchanged."))
        return False
    if text == "/context":
        _print_context(engine)
        return False
    if text == "/cost":
        _print_cost(engine)
        return False
    if text in ("/config", "/settings"):
        _print_config(engine, renderer)
        return False
    if text == "/permissions":
        _print_permissions(engine)
        return False
    if text == "/resume":
        print(f"Resume this engagement with: grypton resume {engine.ws.slug}")
        return False
    if text == "/status":
        _print_status(engine, renderer)
        return False
    if text == "/summary":
        _print_summary(engine, renderer)
        return False
    if text == "/plan":
        directive = engine.ws.load_meta().last_directive.strip()
        print(bold("Kryptex directive:"))
        print(_wrap(_redact_display(directive) or "No directive has been recorded yet.", "  "))
        return False
    if text == "/findings" or text.startswith("/findings "):
        _, _, argument = text.partition(" ")
        try:
            limit = _command_limit(argument, 20)
        except ValueError as exc:
            print(yellow(f"Usage: /findings [1-50] ({exc})"))
            return False
        _print_findings(engine, limit)
        return False
    if text in ("/surface", "/tested"):
        doc = {"/surface": "attack-surface.md",
               "/tested": "tested-techniques.md"}[text]
        p = engine.ws.root / doc
        print(p.read_text(errors="replace") if p.exists() else "(empty)")
        return False
    if text == "/scope":
        print(engine.ws.load_constraints().to_prompt_block())
        return False
    if text == "/model":
        models = engine.current_models()
        print(f"Kraude    {models['kraude']['route']} · {models['kraude']['effort']} · OpenClaude\n"
              f"Kryptex   {models['kryptex']['route']} · {models['kryptex']['effort']} · OpenClaude\n"
              f"Validator {models['validator']['route']} · {models['validator']['effort']} "
              f"(P1/P2 automatic)")
        print(dim("Change one with /model kraude ROUTE [EFFORT] or "
                  "/model kryptex ROUTE [EFFORT]."))
        return False
    if text == "/models" or text.startswith("/models "):
        search = text[len("/models"):].strip()
        asyncio.create_task(_print_model_catalog(search))
        return False
    if text.startswith("/model "):
        try:
            parts = shlex.split(text)
        except ValueError as exc:
            print(yellow(f"Could not parse model command: {exc}"))
            return False
        if len(parts) not in {3, 4} or parts[1].lower() not in {
                "kraude", "worker", "kryptex", "manager"}:
            print(yellow("Usage: /model kraude|kryptex ROUTE [EFFORT]"))
            return False
        try:
            engine.request_model_switch(
                parts[1],
                parts[2],
                parts[3] if len(parts) == 4 else "",
            )
        except ValueError as exc:
            print(yellow(str(exc)))
        return False
    if text in ("/audit", "/review"):
        _print_audit(engine)
        return False
    if text == "/clear":
        if sys.stdout.isatty():
            print("\033[2J\033[H", end="")
        else:
            print("\n" * 3)
        return False
    if text.startswith("/note "):
        note = text[len("/note "):].strip()
        if not note:
            print(yellow("Usage: /note <text>"))
            return False
        engine.ws.add_standing_instruction(f"[OPERATOR NOTE] {note}")
        engine.ws.append_progress("Operator note saved for the engagement.")
        print(green("◆ Note saved. It will remain visible to Kryptex and Kraude without a manager call."))
        return False
    if text in ("/activity", "/flows", "/history") or \
            text.startswith(("/activity ", "/flows ", "/history ")):
        command, _, argument = text.partition(" ")
        try:
            limit = _command_limit(argument, 8 if command != "/history" else 5)
        except ValueError as exc:
            print(yellow(f"Usage: {command} [1-50] ({exc})"))
            return False
        if command == "/activity":
            _print_activity(engine, limit)
        elif command == "/flows":
            _print_flows(engine, limit)
        else:
            _print_history(engine, limit)
        return False
    if text == "/view" or text.startswith("/view "):
        _, _, requested = text.partition(" ")
        if not requested:
            print(f"Live stream mode: {renderer.view}. Use `/view quiet`, `/view normal`, or `/view full`.")
        elif renderer.set_view(requested):
            print(green(f"◆ Live stream set to {renderer.view}. Evidence capture is unchanged."))
        else:
            print(yellow("Usage: /view quiet|normal|full"))
        return False
    if text.startswith("/worker "):
        engine.submit_user(text[len("/worker "):].strip(), to_worker=True)
        return False
    if text.startswith("!"):
        _run_local_inspection(engine, text[1:].strip())
        return False
    # Apply stop-intent ONLY to a single-line message; a paste body of HTTP
    # requests / cookies / code might happen to contain "stop" inside it and
    # must not trigger a halt.
    if "\n" not in text and _is_stop_intent(text):
        engine.request_stop("user asked to stop in chat")
        print(cyan("◆ Stopping — finishing the current step, then halting. "
                   "(Press Ctrl-C for an immediate stop.)"))
        return True
    try:
        text = _expand_workspace_references(engine, text)
    except ValueError as exc:
        print(yellow(str(exc)))
        return False
    engine.submit_user(text, to_worker=False)
    return False


class _PasteParser:
    """Stream-fed parser that turns terminal input (which may contain bracketed-
    paste markers) into complete user messages, accumulating multi-line pastes
    as a single message instead of one-per-line.
    """

    def __init__(self):
        self._state = "normal"            # "normal" | "paste"
        self._buf: list[str] = []

    def feed(self, raw_line: str):
        """Yield zero or more complete messages produced by this input chunk."""
        line = raw_line
        while line:
            if self._state == "normal":
                j = line.find(_PASTE_START)
                if j < 0:
                    text = line.rstrip("\r\n")
                    if text:
                        yield text
                    line = ""
                else:
                    pre = line[:j].rstrip("\r\n")
                    if pre.strip():
                        self._buf.append(pre)        # typed prefix joins the paste
                    self._state = "paste"
                    line = line[j + len(_PASTE_START):]
            else:                                    # paste mode
                j = line.find(_PASTE_END)
                if j < 0:
                    self._buf.append(line)
                    line = ""
                else:
                    self._buf.append(line[:j])
                    full = "".join(self._buf).rstrip("\r\n")
                    self._buf = []
                    self._state = "normal"
                    if full.strip():
                        yield full
                    line = line[j + len(_PASTE_END):]


async def _input_loop(engine, renderer: Renderer) -> None:
    is_tty = sys.stdin.isatty()
    if is_tty:
        # prompt_toolkit redraws the active line after asynchronous renderer
        # output.  Without it, streamed tool events overwrite `❯` and make the
        # console look broken as soon as Kraude starts working.
        try:
            from prompt_toolkit import PromptSession
            from prompt_toolkit.formatted_text import ANSI
            from prompt_toolkit.patch_stdout import patch_stdout
        except ImportError:
            pass
        else:
            session = PromptSession()
            with patch_stdout(raw=True):
                while True:
                    try:
                        raw = await session.prompt_async(ANSI("\x1b[36m❯ \x1b[0m"))
                    except EOFError:
                        return
                    except KeyboardInterrupt:
                        engine.request_stop("interrupt at console prompt")
                        return
                    if _route_input(engine, renderer, raw):
                        return

    # A non-interactive pipe has no prompt.  Keep the small stdlib fallback for
    # unusual terminals where prompt_toolkit is not installed.
    if is_tty:
        try:
            sys.stdout.write("\x1b[?2004h")   # enable bracketed paste
            sys.stdout.flush()
        except Exception:
            pass
    try:
        loop = asyncio.get_running_loop()
        parser = _PasteParser()
        while True:
            if is_tty:
                sys.stdout.write(cyan("\n ❯ "))
                sys.stdout.flush()
            raw = await _readline(loop)
            if not raw:
                return
            for msg in parser.feed(raw):
                if _route_input(engine, renderer, msg):
                    return
    finally:
        if is_tty:
            try:
                sys.stdout.write("\x1b[?2004l")  # disable bracketed paste
                sys.stdout.flush()
            except Exception:
                pass


async def _readline(loop: asyncio.AbstractEventLoop) -> str:
    """Read stdin without a permanent executor thread blocking CLI shutdown."""
    try:
        fd = sys.stdin.fileno()
    except (AttributeError, OSError, ValueError):
        return await asyncio.to_thread(sys.stdin.readline)

    ready = loop.create_future()

    def on_readable() -> None:
        loop.remove_reader(fd)
        if ready.done():
            return
        try:
            ready.set_result(sys.stdin.readline())
        except Exception as exc:
            ready.set_exception(exc)

    try:
        loop.add_reader(fd, on_readable)
    except (AttributeError, NotImplementedError, OSError, PermissionError):
        return await asyncio.to_thread(sys.stdin.readline)
    try:
        return await ready
    finally:
        loop.remove_reader(fd)
