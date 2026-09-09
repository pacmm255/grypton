# Krypton — Architecture

## The idea

A lone Claude Code session is a brilliant operator with no stamina: it concludes
"nothing found" and stops, and nagging it with "continue" is low-signal. Krypton
fixes this by putting a **second model in the driver's seat**. Codex (the manager,
*Kryptex*) never does the hands-on work — it *watches* the Claude worker (*Kraude*),
calls the next move, validates the result, and refuses to let the hunt end. It is a
rally co-driver reading the road for a faster-but-tunnel-visioned driver.

```
                        ┌──────────────────────── you ────────────────────────┐
                        │  talk to the manager (default) · /worker to the worker │
                        └───────────────────────────┬───────────────────────────┘
                                                     │ chat.py (REPL + live render)
                                                     ▼
        ┌───────────────────────────────  engine.py  ───────────────────────────────┐
        │  NON-STOP LOOP, every turn:                                                 │
        │   1. worker.run_turn(directive)         (one continuous Claude session)     │
        │   2. detect deltas from workspace ledgers (new findings / surface)          │
        │   3. anti-fabrication scan of the worker's message                          │
        │   4. exhaustion signal (no new surface/finding for N turns)                 │
        │   5. manager.direct(full vision)  → structured Directive                    │
        │   6. apply severity verdicts · enforce non-stop · persist · render          │
        │   7. feed Directive back as the next worker turn                            │
        └───────┬──────────────────────────────────────────────────────────┬─────────┘
                │ worker.py (kraude)                                         │ manager.py (kryptex)
                ▼                                                            ▼
   claude -p --input-format stream-json --resume <clone>          codex exec [resume <id>] --json
   --model claude-opus-4-8 --effort max --mcp-config …            --output-schema directive_schema.json
   (ONE process, auto-compacted, crash-resumable)                 (ONE continuous codex session)
                │                                                            │
                ├───────────────── shared workspace (fcntl-locked ledgers) ──┤
                ▼                                                            ▼
        toolserver.py (MCP stdio)  ←──  tools.py  ──→  Goja · httpx · browser · install · research
        record_finding / attack_surface_add / tested_technique_log / prior_attempts / …
                                                     │
                                       targets/<slug>/{findings,attack-surface,
                                       tested-techniques,scope-rules,progress}.md + ledgers
```

## Why these mechanisms

**One continuous worker session (not new sessions).** `worker.py` runs a single
`claude -p` in bidirectional `stream-json`, resuming the cloned Init 0 by UUID. Each
"turn" writes the next user message to stdin and reads events until `result`. The
process lives for the whole engagement, so Claude's own **auto-compaction** manages
context. If the process dies, `ensure_started` re-spawns `--resume <same uuid>` —
continuity is on disk. The line reader is unbounded because tool-result lines reach
many MB.

**Structured manager directives.** `manager.py` calls `codex exec` constrained by
`--output-schema` (strict-mode JSON: every key required, `additionalProperties:false`)
and reads the result from `-o last.json`. The session id is captured from the
`--json` stream once and reused via `codex exec resume <id>` for full memory. Codex's
custom provider key is sourced from `~/.codex/auth.json` into the subprocess env.

**Non-stop is structural, not a prompt plea.** The engine simply never exits to a
finish state (`engine.run`). Exhaustion (no new surface/finding for
`exhaustion_threshold` turns) flips a flag that forces the manager to emit an
`exhaustion_breaker` — its own creative expansion strategy. A soft manager stop is
overridden; only a hard scope/authorization reason (`_is_hard_stop`) ends the loop.

**Manager vision & independent validation.** Every turn the manager receives the
worker's full message + tool summary + the rendered docs, and runs with the
workspace as its cwd so it can open files itself. New findings are validated
independently against `severity_schema.json`; verdicts are written back into
`findings.md` beside the worker's claim.

**Durable, manager-visible state.** Worker tool calls go through the Krypton MCP
server (`toolserver.py`), which writes append/update-by-id JSONL **ledgers** (the
source of truth) behind an `fcntl` lock; Markdown views are regenerated atomically.
The engine reads ledger deltas to know what changed — this is how a worker tool call
becomes manager-visible. The same ops are exposed as the `krypton-tool` CLI fallback.

**Constraints are never forgotten.** `workspace.Constraints` (scope-rules) render
into a block injected into the manager every turn and the worker's system prompt +
`CLAUDE.md`; the worker re-reads `scope-rules.md` each turn so live additions survive
compaction. Out-of-scope severities / excluded classes are suppressed from findings.

## Session isolation (the safety core — `sessions.py`)

1. **Resolve** the named live session (`resolve_named_session`) by content match,
   ranked by size+recency — picks the user's big pre-trained session.
2. **Freeze** (`freeze_init0`): copy transcript + the entire sidecar tree to
   `sessions/init0/`, checksum it, and `chmod` everything read-only. The original is
   only read.
3. **Clone** (`clone_for_target`): allocate a new UUID + a project dir derived from
   the worker cwd, then **byte-stream-rewrite** the transcript — original sidecar
   absolute-path prefix → clone prefix, then original UUID → new UUID — so the clone
   references only itself. Tool-result blobs are copied verbatim; subagent transcripts
   are rewritten too. `_assert_write_safe` refuses any write into the original project
   dir or the frozen snapshot.

This is verified end-to-end in `tests/run_all.py` and was confirmed byte-for-byte
against the real 258 MB session (sha256 unchanged before/after freeze).

## Backends & testing

`config.CONFIG.backend` selects `real` (drives claude+codex) or `mock`
(`mockbackends.py`: deterministic emulators with the same async interfaces that
produce real workspace side-effects). The offline suite exercises the entire loop —
isolation, validation, exhaustion→expansion, non-stop override, hard-stop honouring,
anti-fabrication, constraints, dedup, MCP protocol, CLI — with zero network. Live
smokes (`live_smoke.py`, `live_engine.py`) validate the real seams.

## Module map

| File | Role |
|------|------|
| `config.py` | Paths, model/effort, project-dir encoding, binary discovery, tunables |
| `sessions.py` | Resolve / freeze / clone with guaranteed isolation |
| `workspace.py` | Per-target dirs, JSONL ledgers + Markdown views, constraints |
| `worker.py` | Kraude — continuous Claude stream-json driver |
| `manager.py` | Kryptex — Codex structured-directive + severity validation driver |
| `engine.py` | The non-stop orchestration loop |
| `antifab.py` | Fabrication detection (ported from the proven keep-going hook) |
| `tools.py` | Goja, httpx, browser, installer, research, proxy flows |
| `toolserver.py` | MCP stdio server + `krypton-tool` CLI (shared impls) |
| `prompts.py` + `prompts/*.md` | Editable system prompts + worker config files |
| `chat.py` | CLI chat (talk to manager, watch worker, inject to either) |
| `cli.py` | `init/resume/freeze/sessions/status/stop/doctor/test/tool` |
| `mockbackends.py` | Deterministic offline worker/manager for tests |
| `bin/{krypton,kraude,kryptex,krypton-mcp,krypton-tool}` | Launchers / patched-CLI entry points |
