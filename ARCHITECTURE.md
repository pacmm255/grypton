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
 OpenCode + tools      OpenCode, tools denied
        |                  |
        +--------+---------+
                 |
       role-specific authenticated
       loopback OpenClaude gateways
                 |
        selected public routes
        and provider key pools
                 |
        +--------+---------+
        |                  |
 zai-coding-plan/...     go/...
 or another selected    or another selected
 OpenClaude route       OpenClaude route

 workspace ledgers and captures
                 |
       P1/P2 automatically
       P3-P5 when requested
                 v
        fresh Codex validator
        GPT-6 Astra max
        direct, ephemeral, schema-bound,
        read-only, tools denied
```

## Model and transport boundary

Kraude and Kryptex use OpenCode as their session and tool host. Their model
requests do not go directly from OpenCode to Z.AI or OpenCode Go. Grypton starts
one long-lived OpenClaude sidecar for each role, creates an authenticated
`127.0.0.1` Messages gateway, and registers that gateway as OpenCode's only
model provider. OpenClaude translates the Messages request to the selected
route's native protocol.

The sidecar imports the supported modules from the local checkout at
`/root/openclaude`; Grypton does not copy OpenClaude's source. The checkout and
its `openclaude.config.json` must be present. `GRYPTON_OPENCLAUDE_HOME` and
`GRYPTON_OPENCLAUDE_CONFIG` can select different paths.

The default public routes are `zai-coding-plan/glm-5.3` at `max` for Kraude and
`go/muse-spark-1.3-contributor` at `xhigh` for Kryptex. OpenClaude's local
catalog is the source of truth. Grypton validates availability, effort support,
and Kraude's tool capability before a real run. Legacy `opencode-go/...` input
is normalized to `go/...` instead of being stored as a second provider name.

Astra is outside this transport. `CodexValidator` starts a fresh direct Codex
process using `gpt-6-astra` at `max`. Kryptex directs the engagement, but Astra
alone can validate evidence.

## Credentials and automatic key failover

Provider credentials remain inside OpenClaude. A pool contains the configured
primary credential followed by the provider's `keyFile`; entries are
deduplicated. In the bundled setup, the Go provider's key file is `/root/open`.
Neither keys nor the local gateway token appear in OpenCode configuration,
engagement metadata, reports, or event logs.

OpenClaude classifies an upstream failure before deciding what can help:

| Upstream result | Action |
| --- | --- |
| 401 or 402 | Bench the key and use the next usable key. |
| 403 identified as data policy, blocked account, credits, quota, or billing | Bench the key and use the next usable key. |
| 429 identified as a plan/account usage limit, credits, or insufficient balance | Bench the key and use the next usable key. |
| Connection failure, 408, 425, or 5xx | Retry with bounded backoff when the configured retry window permits it. |
| Invalid request, unknown model, unsupported effort, ordinary permission denial, tool error, or scope denial | Return the error without spending another key. |

The role gateway keeps its spent-key cooldown state across turns. OpenClaude
never replays a request after response streaming has begun. This prevents one
model answer or tool request from being emitted twice. A model switch closes
the old role gateway, so the new selection gets a clean transport lifecycle.

Gateway events are sanitized before they reach Grypton. The engine records
route, protocol, message and tool counts, effective effort, safe notices, and
short key fingerprints in `transcripts/openclaude.events.jsonl`. It never
records a key.

## Engine loop

The engine starts Kraude with a target-specific prompt, current scope, embedded
operating skills, and target-type playbooks. OpenCode resumes one Kraude session
across turns while the chosen model stays the same. Tool events stream into the
terminal while structured Grypton MCP calls update locked ledgers and private
flow captures.

After each worker turn, the engine detects new surface and findings, checks text
claims against workspace artifacts, tracks idle and exhaustion streaks, and
gives Kryptex the worker report, complete tool summary, scope, recent ledgers,
and progress. Kryptex returns strict JSON with one concrete next burst. Invalid
JSON gets one schema repair attempt; a provider failure falls back to a
deterministic, bounded, in-scope directive.

Operators can choose models in three places:

- global defaults saved by `grypton models --set-kraude ...` and
  `--set-kryptex ...`;
- per-run `--kraude-model`, `--kraude-effort`, `--kryptex-model`, and
  `--kryptex-effort` flags;
- interactive `/model kraude ROUTE [EFFORT]` and
  `/model kryptex ROUTE [EFFORT]` commands.

The effective route and effort are stored in engagement metadata. Resume uses
those saved values unless run flags override them. An interactive change waits
for a safe role boundary, closes the old provider session, starts a fresh
session for that role, and records the change in `.ledger/model-switches.jsonl`.
Durable workspace records carry the engagement context into the new session;
an old vendor transcript is not replayed into a different model.

## Validation boundary

Kryptex's severity array is discarded. New P1 and P2 findings are validated
through `CodexValidator`; P3-P5 findings remain `validation-not-requested`
unless the operator runs `grypton validate TARGET FINDING` or explicitly asks
for review. The validator copies only explicitly referenced workspace artifacts
into a bounded prompt. Its byte budget is divided across every cited artifact
and includes both ends of large captures, so an early HTML response cannot hide
a later control.

The Astra process is ephemeral, uses a read-only sandbox, disables execution
features, requires a JSON schema, and is rejected if its event stream reports
tool use. Changing Kraude or Kryptex never changes Astra's route, effort, or
automatic P1/P2 gate.

## Scope and observability

`scope-rules.json` is the source of truth. Host matching supports exact hosts,
explicit wildcard subdomains, and CIDRs. A bare domain does not silently permit
every subdomain. Structured HTTP, Goja, browser, DNS, TLS, port, httpx, and
subfinder tools enforce these rules before action. Goja has a managed PID and
Grypton stops only the process it started.

Each structured call appends `.ledger/tool-calls.jsonl`. HTTP tools also create
private `flows/flow-*.http` request and response captures. Provider transports
append redacted raw event streams and per-call metadata to `transcripts/`,
including public route, effort, session ID, timing, usage, cost, prompt and
output hashes, transport `openclaude` route, and whether the call completed.

OpenCode success payloads use `state.output`; rejected and timed-out calls use
`state.error`. The worker normalizes both into visible tool results. The MCP
transport has a 120-second outer ceiling, while network tools retain smaller
operation-specific limits. Full HTTP captures are never trimmed; only the
model-facing response preview is bounded.

`grypton stop` writes a stop marker. The engine checks it every second during a
worker turn, terminates the provider process group, closes the OpenClaude
sidecar, and saves session IDs and the turn index. Hard scope or authorization
stops are binding. Idle or ordinary blocker responses become another concrete
action inside scope. Authentication probes have a cumulative turn-to-turn
budget. A target defense signal ends that probe family immediately instead of
being retried or evaded.

`grypton audit` reads the canonical ledgers and verifies the saved model routes,
clean provider exits, required P1/P2 Astra coverage, explicitly requested
lower-level reviews, network scope, referenced flow existence, and the empty
top-level `target/`. `grypton report` renders those final verdicts without
treating every recorded candidate as confirmed.

## Active modules

| Module | Responsibility |
| --- | --- |
| `config.py` | global and per-engagement role selections, state layout, binary discovery |
| `openclaude.py` | sanitized catalog access and role-specific sidecar lifecycle |
| `resources/openclaude_sidecar.mjs` | OpenClaude module bridge and authenticated local gateway |
| `providers.py` | OpenCode-over-OpenClaude sessions and direct ephemeral Codex validation |
| `worker.py` | selectable Kraude turn adapter and streamed tool events |
| `manager.py` | selectable Kryptex direction, chat, and Astra handoff |
| `engine.py` | persistent autonomous loop, safe model switching, and stop/recovery logic |
| `workspace.py` | private ledgers, rendered documents, constraints, and model persistence |
| `tools.py` | scoped HTTP, Goja, captures, recon, and installation |
| `toolserver.py` | MCP registry, audit dispatch, and matching CLI |
| `scenarios.py` | target-type kickoff playbooks |
| `local_lab.py` | deterministic loopback integration target |
| `chat.py` | live terminal renderer, model controls, and operator steering |
| `web.py` | read-only loopback operations dashboard |
| `reporting.py` | integrity audit and final report rendering |
| `cli.py` | run, model, review, report, tools, lab, dashboard, and doctor commands |
