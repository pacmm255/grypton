"""The Krypton chat — a CLI conversation like Claude Code / Codex (R10, R13).

You talk to **Kryptex** (the manager) by default; `/worker <msg>` talks to **Kraude**
directly. Kryptex replies to your messages in REAL TIME (concurrent with whatever
Kraude is doing) and remembers them. The terminal shows *everything*: system init,
Kraude's thinking + output, every tool call with its command/code, tool results,
Codex's own reasoning/commands, directives, findings, and severity verdicts.
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
import sys
import textwrap

# Natural-language stop intent: a message made up ONLY of stop words + filler
# (e.g. "ok enough you can stop now") halts the engine. A nuanced message like
# "stop testing CORS but keep going" is NOT a stop — it routes to Kryptex.
_STOP_WORDS = {"stop", "halt", "abort", "quit", "cease", "terminate", "enough", "kill", "end", "wrap"}
_STOP_FILLER = {"ok", "okay", "you", "youre", "can", "could", "it", "now", "please", "the",
                "this", "that", "thats", "krypton", "kryptex", "everything", "all", "hunt",
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
    disp = name.replace("mcp__krypton__", "krypton.").replace("mcp__", "")
    head = yellow(f"  ⚙ Kraude → {disp}")
    body = None
    if name == "Bash" and "command" in inp:
        desc = inp.get("description", "")
        if desc:
            head += dim(f"  — {desc}")
        body = "$ " + str(inp["command"])
    elif name == "Write" and "file_path" in inp:
        head += "  " + str(inp["file_path"])
        body = str(inp.get("content", ""))
    elif name == "Edit" and "file_path" in inp:
        head += "  " + str(inp["file_path"])
        body = f"- {inp.get('old_string', '')}\n+ {inp.get('new_string', '')}"
    elif name in ("Read", "NotebookEdit") and "file_path" in inp:
        head += "  " + str(inp["file_path"])
    elif name in ("WebFetch", "WebSearch"):
        head += "  " + str(inp.get("url") or inp.get("query", ""))
    elif inp:
        body = json.dumps(inp, ensure_ascii=False)
    return head, body


class Renderer:
    """Engine event sink → terminal. Shows everything, colored."""

    def __init__(self):
        self._turn = 0
        self._line_open = False     # a streamed line is awaiting its newline
        self._stream_mode = None    # None | 'text' | 'thinking'
        self._streamed_text = False  # did final text stream this turn?

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
            content = d.get("content", "")
            label = red("  ↳ result (error):") if d.get("is_error") else dim("  ↳ result:")
            print(label)
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
            if fp == "claude":
                header = "  ◆ Kryptex (manager · via Claude fallback this turn):"
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

        elif kind == "verdict":
            v = d.get("verdict", {})
            print(blue(f"  ⚖ Kryptex verdict on {d.get('finding_id','')}: "
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
            print(yellow(f"  ⤴ Kryptex (Codex) failed — Claude is taking over as the "
                         f"fallback manager for this turn."))
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
Krypton chat commands:
  <text>            message Kryptex (the manager) — replies in real time
  /worker <text>    message Kraude (the worker) directly
  /stop             stop the engagement
  /status           run status
  /findings         print findings.md
  /surface          print attack-surface.md
  /help             this help
"""


async def interact(engine) -> None:
    print(bold(cyan("\n╔══ Krypton ══╗  ")) +
          dim(f"target={engine.target}  mode={engine.backend}  (/help for commands)\n"))
    loop_task = asyncio.create_task(engine.run())
    input_task = asyncio.create_task(_input_loop(engine))
    try:
        done, _ = await asyncio.wait({loop_task, input_task}, return_when=asyncio.FIRST_COMPLETED)
        if loop_task in done:
            input_task.cancel()
        else:
            await loop_task
    finally:
        for t in (loop_task, input_task):
            if not t.done():
                t.cancel()
        try:
            await loop_task
        except (asyncio.CancelledError, Exception):
            pass


# Bracketed-paste markers (DEC mode 2004). Modern terminals (iTerm2, gnome-
# terminal, xterm, alacritty, kitty, vscode, Windows Terminal) wrap pasted text
# in these so we can accumulate the paste as ONE message instead of treating each
# \n as a separate submit.
_PASTE_START = "\x1b[200~"
_PASTE_END = "\x1b[201~"


def _route_input(engine, text: str) -> bool:
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
        m = engine.ws.load_meta()
        print(cyan(f"◆ turns={engine.turn_index} status={m.status} "
                   f"findings={len(engine.ws.findings.all())} "
                   f"surface={len(engine.ws.surface.all())} "
                   f"P1s={len(engine.ws.confirmed_p1s())}"))
        return False
    if text in ("/findings", "/surface"):
        doc = "findings.md" if text == "/findings" else "attack-surface.md"
        p = engine.ws.root / doc
        print(p.read_text(errors="replace") if p.exists() else "(empty)")
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


async def _input_loop(engine) -> None:
    is_tty = sys.stdin.isatty()
    if is_tty:
        try:
            sys.stdout.write("\x1b[?2004h")   # enable bracketed paste
            sys.stdout.flush()
        except Exception:
            pass
    try:
        loop = asyncio.get_event_loop()
        parser = _PasteParser()
        while True:
            raw = await loop.run_in_executor(None, sys.stdin.readline)
            if not raw:
                return
            for msg in parser.feed(raw):
                if _route_input(engine, msg):
                    return
    finally:
        if is_tty:
            try:
                sys.stdout.write("\x1b[?2004l")  # disable bracketed paste
                sys.stdout.flush()
            except Exception:
                pass
