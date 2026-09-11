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
import shutil
import sys
import textwrap
import time
from pathlib import Path

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
    head = yellow(f"  ⚙ Kraude → {disp}")
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


class Renderer:
    """Engine event sink → terminal. Shows everything, colored."""

    def __init__(self):
        self._turn = 0
        self._line_open = False     # a streamed line is awaiting its newline
        self._stream_mode = None    # None | 'text' | 'thinking'
        self._streamed_text = False  # did final text stream this turn?
        # Evidence is always retained in the workspace. This only controls how
        # much of the live stream reaches the terminal.
        self.view = "normal"        # quiet | normal | full

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
            print(bold(f"▶ Turn {self._turn}") + dim("   · Kraude working…"))

        elif kind == "heartbeat":
            print(dim(f"  … Kraude still working — {d.get('elapsed', 0)}s, "
                      f"{d.get('tools', 0)} tool call(s) so far"))

        elif kind == "worker_system":
            mcp = ", ".join(d.get("mcp") or []) or "—"
            print(blue(f"  ⚙ session online — model={d.get('model','?')} "
                       f"tools={d.get('tools','?')} mcp=[{mcp}]"))

        elif kind == "worker_thinking":
            if self.view != "quiet":
                self._stream("thinking", dim("  🧠 Kraude (thinking):"), d.get("text", ""), dimmed=True)

        elif kind == "worker_delta":
            self._stream("text", green("  ▼ Kraude:"), d.get("text", ""))
            self._streamed_text = True

        elif kind == "worker_tool":
            head, body = _render_tool(d.get("name"), d.get("input"))
            print(head)
            if body:
                print(_block(body))

        elif kind == "worker_tool_result":
            content = _redact_display(d.get("content", ""))
            label = red("  ↳ result (error):") if d.get("is_error") else dim("  ↳ result:")
            print(label)
            if self.view == "quiet":
                first = next((line.strip() for line in str(content).splitlines() if line.strip()),
                             "(empty result)")
                print(_wrap(first[:360] + (" …" if len(first) > 360 else ""), "      "))
            elif self.view == "full":
                print(_block(content, maxlen=3600, maxlines=100))
            else:
                print(_block(content, maxlen=1400, maxlines=30))

        elif kind == "worker_turn":
            txt = (d.get("text") or "").strip()
            if txt and not self._streamed_text:
                print(green("  ▼ Kraude:"))
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
            header = "  ◆ Kryptex (manager):"
            if fp:
                header = f"  ◆ Kryptex (manager · {fp} fallback):"
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
                print(yellow(f"  💬 Kryptex → you: {d['to_user']}"))

        elif kind == "kryptex_chat":
            print()
            print(bmagenta("  💬 Kryptex (live reply):"))
            print(_wrap(d.get("reply", ""), "      "))
            if d.get("remember"):
                print(dim(f"      ⟲ remembered: {d['remember']}"))
            if d.get("disposition"):
                print(dim(f"      → disposition: {d['disposition']}"))
            print()

        elif kind == "finding":
            f = d.get("finding", {})
            print(bgreen(f"  ★ FINDING {f.get('id','')}: {f.get('title','')} "
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
Grypton operator console

  <text>                 message Kryptex; it replies and relays actionable intent
  /worker <text>         send a concrete instruction to Kraude's next work burst
  /note <text>           save an operator note without spending a manager call
  /summary               compact live state: coverage, finding, and next-action view
  /status                current turn and coverage counters
  /plan                  show Kryptex's current directive
  /activity [N]          recent audited tool calls (default 8)
  /flows [N]             recent capture IDs and sizes (default 8; bodies stay private)
  /history [N]           recent worker-turn summaries (default 5)
  /findings              findings ledger
  /surface               attack-surface ledger
  /tested                tested-techniques ledger
  /scope                 binding scope and standing instructions
  /models                pinned model routes
  /audit                 evidence, scope, and validator integrity check
  /view quiet|normal|full control live-stream detail; current mode is shown on /status
  /clear                 clear the visible terminal buffer
  /stop                  stop after the active worker step
  /help                  this help
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
    print(cyan(
        f"◆ status={meta.status} · turn={engine.turn_index} · elapsed={elapsed // 60}m{elapsed % 60:02d}s "
        f"· findings={len(engine.ws.findings.all())} · surface={len(engine.ws.surface.all())} "
        f"· P1s={len(engine.ws.confirmed_p1s())} · stream={renderer.view}"
    ))


def _print_summary(engine, renderer: Renderer) -> None:
    """A decision-oriented snapshot intended for use while a turn is running."""
    meta = engine.ws.load_meta()
    constraints = engine.ws.load_constraints()
    findings = engine.ws.findings.all()
    confirmed = engine.ws.confirmed_findings()
    latest = findings[-1] if findings else {}
    print(bold(cyan("\n╭─ Grypton live summary")))
    print(f"│ target      {meta.target} ({meta.target_type}) · {meta.status} · turn {engine.turn_index}")
    print(f"│ coverage    surface={len(engine.ws.surface.all())} · tested={len(engine.ws.tested.all())} "
          f"· findings={len(confirmed)}/{len(findings)} confirmed")
    print(f"│ scope       {', '.join(constraints.in_scope) or '—'}")
    if latest:
        verdict = latest.get("manager_verdict") or {}
        state = verdict.get("verdict") or latest.get("status", "recorded")
        severity = verdict.get("severity") or latest.get("severity", "?")
        print(f"│ latest      {latest.get('id', '?')} · {severity} · {state} · "
              f"{str(latest.get('title', ''))[:110]}")
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
          f"required validation gaps={len(result.get('unvalidated_findings', []))}")


async def interact(engine, renderer: Renderer | None = None) -> None:
    from . import config

    print(bold(cyan("\n╔══ Grypton operator console ══╗")))
    print(dim(f"target={engine.target} · type={engine.target_type} · backend={engine.backend}"))
    print(dim(f"Kraude {config.WORKER_MODEL} · {config.WORKER_EFFORT}  |  "
              f"Kryptex {config.MANAGER_MODEL} · {config.MANAGER_EFFORT}  |  "
              f"Astra {config.VALIDATOR_MODEL} · {config.VALIDATOR_EFFORT}"))
    print(dim("Type `/summary` for the operating picture or `/help` for console commands.\n"))
    loop_task = asyncio.create_task(engine.run())
    if renderer is None:
        candidate = getattr(engine.emit, "__self__", None)
        renderer = candidate if isinstance(candidate, Renderer) else Renderer()
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
    if text in ("/findings", "/surface", "/tested"):
        doc = {"/findings": "findings.md", "/surface": "attack-surface.md",
               "/tested": "tested-techniques.md"}[text]
        p = engine.ws.root / doc
        print(p.read_text(errors="replace") if p.exists() else "(empty)")
        return False
    if text == "/scope":
        print(engine.ws.load_constraints().to_prompt_block())
        return False
    if text == "/models":
        from . import config
        print(f"Kraude    {config.WORKER_MODEL} · {config.WORKER_EFFORT}\n"
              f"Kryptex   {config.MANAGER_MODEL} · {config.MANAGER_EFFORT}\n"
              f"Validator {config.VALIDATOR_MODEL} · {config.VALIDATOR_EFFORT} (P1/P2 automatic)")
        return False
    if text == "/audit":
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
    # Apply stop-intent ONLY to a single-line message; a paste body of HTTP
    # requests / cookies / code might happen to contain "stop" inside it and
    # must not trigger a halt.
    if "\n" not in text and _is_stop_intent(text):
        engine.request_stop("user asked to stop in chat")
        print(cyan("◆ Stopping — finishing the current step, then halting. "
                   "(Press Ctrl-C for an immediate stop.)"))
        return True
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
                sys.stdout.write(cyan("\n grypton› "))
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
