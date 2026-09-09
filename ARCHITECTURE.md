# Grypton architecture

```text
operator / CLI / loopback dashboard
                 |
                 v
        persistent Engine loop
                 |
        +--------+---------+
        |                  |
        v                  v
 Kraude worker        Kryptex manager
 OpenCode             OpenCode
 GLM 5.3 max          Muse Spark 1.3 xhigh
 native + MCP tools   tools denied
        |                  |
        +--------+---------+
                 |
        workspace ledgers and captures
                 |
          each new finding
                 v
        fresh Codex validator
        GPT-6 Astra max
        ephemeral, schema-bound, tools denied
```

The engine starts Kraude with a target-specific prompt, current scope, embedded
operating skills, and target-type playbooks. OpenCode resumes one worker session
across turns. Tool events stream into the terminal while structured Grypton MCP
calls update locked ledgers and private flow captures.

After each worker turn the engine detects new surface and findings, checks text
claims against workspace artifacts, tracks idle/exhaustion streaks, and gives
Kryptex the worker report, complete tool summary, scope, recent ledgers, and
progress. Kryptex returns strict JSON with one concrete next burst. Invalid JSON
gets one schema repair attempt; provider failure falls back to a deterministic,
bounded in-scope directive.

Kryptex's severity array is discarded. Each new finding is validated through
`CodexValidator`, which copies only explicitly referenced artifacts from within
the engagement workspace into a bounded prompt. The byte budget is divided
across every cited artifact and includes both ends of large captures, so an
early HTML response cannot hide a later control. The process uses `gpt-6-astra`
at `max`, runs ephemerally in a read-only sandbox, disables execution features,
requires a JSON schema, and is rejected if the event stream reports tool use.

## Scope and observability

`scope-rules.json` is the source of truth. Host matching supports exact hosts,
explicit wildcard subdomains, and CIDRs. A bare domain does not silently permit
every subdomain. Structured HTTP, Goja, browser, DNS, TLS, port, httpx, and
subfinder tools enforce these rules before action. Goja has a managed PID and
Grypton stops only the process it started.

Each structured call appends `.ledger/tool-calls.jsonl`. HTTP tools also create
private `flows/flow-*.http` request/response captures. Provider transports append
redacted raw event streams and per-call metadata to `transcripts/`, including
route, effort, session ID, timing, usage, cost, and prompt/output hashes.

OpenCode success payloads use `state.output`; rejected and timed-out calls use
`state.error`. The worker normalizes both into visible tool results. The MCP
transport has a 120-second outer ceiling, while HTTP and other network tools
retain smaller operation-specific limits. Full HTTP captures are never trimmed;
only the model-facing response preview is bounded.

`grypton stop` writes a stop marker. The engine checks it every second during a
worker turn, terminates the provider process group, and saves session IDs and the
turn index. Hard scope or authorization stops are binding. Idle or ordinary
blocker responses are converted into another concrete action inside scope.
Authentication probes have a cumulative turn-to-turn budget. A target defense
signal ends that probe family immediately instead of being retried or evaded.

`grypton audit` reads the canonical ledgers and verifies route pins, clean
provider exits, Astra coverage, network scope, referenced flow existence, and
the empty top-level `target/`. `grypton report` renders those same final verdicts
without treating every recorded candidate as confirmed.

## Active modules

| Module | Responsibility |
| --- | --- |
| `config.py` | pinned routes, state layout, binary discovery |
| `providers.py` | isolated OpenCode sessions and ephemeral Codex validation |
| `worker.py` | GLM turn adapter and streamed tool events |
| `manager.py` | Spark JSON direction, chat, Astra handoff |
| `engine.py` | persistent autonomous loop and stop/recovery logic |
| `workspace.py` | private ledgers, rendered documents, constraints |
| `tools.py` | scoped HTTP, Goja, captures, recon, installation |
| `toolserver.py` | MCP registry, audit dispatch, matching CLI |
| `scenarios.py` | target-type kickoff playbooks |
| `local_lab.py` | deterministic loopback integration target |
| `chat.py` | live terminal renderer and operator steering |
| `web.py` | read-only loopback operations dashboard |
| `reporting.py` | integrity audit and final report rendering |
| `cli.py` | autonomous run, review, report, tools, lab, dashboard, and doctor commands |
