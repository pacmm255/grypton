# Grypton

Grypton is an autonomous, persistent security-testing orchestrator derived from
Krypton's working loop. Kraude performs scoped work with real tools, Kryptex
reviews every turn and supplies the next move, and a separate validator reviews
new findings.

| Role | Runner and plan | Exact route | Effort |
| --- | --- | --- | --- |
| Kraude, worker | OpenCode / Z.AI Coding Plan | `zai-coding-plan/glm-5.3` | `max` |
| Kryptex, manager | OpenCode / Go | `opencode-go/muse-spark-1.3-contributor` | `xhigh` |
| Validator | Codex | `gpt-6-astra` | `max` |

Spark never validates its own worker. For each newly recorded finding, Grypton
collects the explicitly referenced workspace artifacts and starts a fresh,
ephemeral, tool-disabled Astra process with a strict verdict schema.

## Start an engagement

Both target forms work:

```bash
cd /root/grypton/bin
./grypton init --target "go2tr.com"
./grypton init "go2tr.com"
```

Useful controls:

```bash
./grypton init --target "example.test" \
  --in-scope "example.test,*.example.test" \
  --out-scope "status.example.test" \
  -m "Assess the web and API surface"

./grypton status --json
./grypton show example-test
./grypton findings example-test
./grypton surface example-test
./grypton history example-test
./grypton scope example-test
./grypton audit example-test
./grypton report example-test --output report.md
./grypton resume example-test
./grypton stop example-test
./grypton models
./grypton doctor
./grypton scenarios
```

The live terminal shows worker text, every tool request/result, heartbeats,
manager assessment and directive, findings, and Astra verdicts. Type a message
to Kryptex during the run, `/worker ...` to relay directly to Kraude, or `/stop`.
Ctrl-C and `grypton stop` terminate an active provider process instead of waiting
for its full turn timeout.

Finding status follows the independent verdict: `confirmed`,
`needs-more-evidence`, `rejected`, or `validation-pending`. The dashboard and
CLI show confirmed findings separately from recorded candidates. `audit`
checks model routes, provider exits, validator coverage, scope, flow references,
and the required empty `target/` directory; `report` renders the same corrected
ledger state as Markdown or JSON.

State is private under `.state/engagements/<slug>/`. The requested top-level
`target/` directory stays empty, and this fork does not create a `targets/`
directory. The preserved source snapshot lives under `upstream/` and is not
imported by the active package.

## Tool calling

Kraude receives native OpenCode tools and 23 Grypton MCP tools. Structured
network tools check the recorded host and explicit URL port before writing an
audit event. Redirects are captured one hop at a time so an unchecked Location
cannot leave scope. The main
surface includes:

- `http_request`: curl request with bounded output and a full private capture;
- `goja_start`, `goja_request`, `goja_status`, `goja_stop`;
- `proxy_flows`, `flow_read`, `flow_replay` for Burp-like capture work;
- `httpx_probe`, scoped Playwright `browse`, `dns_lookup`, `tls_certificate`, `port_scan`, and
  `subdomain_enum`;
- `attack_surface_add`, `tested_technique_log`, `prior_attempts`, and
  `record_finding`;
- `tool_inventory`, `install_tool`, `research`, `save_research`, and `read_doc`.

Use the same surface manually:

```bash
./grypton tools --target example-test inventory
./grypton tools --target example-test http https://example.test/ --method GET
./grypton tools --target example-test flows
./grypton tools --target example-test flow-read flow-123456
./grypton tools --target example-test flow-replay flow-123456 --url https://example.test/control
```

OpenCode is configured per role with private XDG directories. Kraude can use
tools; Kryptex is tool-denied and receives the turn digest. Provider keys are
copied only into private runtime state for the matching connector and never
printed. The OpenCode Go connector is checked against `/root/open` when that
file exists.

OpenCode tool failures retain their `state.error` text in the live terminal and
turn record. MCP calls use a two-minute outer ceiling while individual network
tools keep their own bounded timeouts. Large responses are previewed to the
model while the complete response remains in the private flow capture.

Invalid-authentication checks share a cumulative budget across turns. A CAPTCHA,
429, WAF challenge, temporary block, or lockout ends that probe family and sends
the worker to passive or unrelated read-only work.

## Local integration target and dashboard

Run the deterministic loopback target in one terminal:

```bash
./grypton lab --port 18767 --log ../.state/lab/requests.jsonl
```

Then exercise the complete live loop in another:

```bash
./grypton init --force --target http://127.0.0.1:18767 \
  --type web --max-turns 3 -m "Map and verify the local profile API"
```

The lab includes linked JavaScript, robots metadata, a debug route, and a
synthetic object-authorization differential. It binds to loopback by default
and records every request without authorization or cookie values.

The operations dashboard is also loopback-only and read-only:

```bash
./grypton serve --port 8765
```

It shows pinned model routes, live provider counts, turns, structured tool
calls, captures, surface records, tested techniques, findings, and Astra state.

## Verification

```bash
python3 -m pytest -q
python3 tests/ui_smoke.py
python3 -m compileall -q grypton tests
./bin/grypton doctor
```

The unit suite exercises both `init` forms, exact routes, the mock autonomous
loop, independent validator separation and fair multi-artifact evidence
snapshots, MCP registry, exact-port scope rejection, redirect protection, HTTP
capture, replay, preserved OpenCode error text, bounded model previews with
complete disk captures, report auditing, review-command parsing, and clean CLI
shutdown. `doctor` checks the exact OpenCode catalogs, both connector
credentials without displaying them, Codex, curl, httpx, Playwright/Chrome,
subfinder, Goja, and the MCP handshake. The implementation contract is in
[`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md).
Live and offline evidence is summarized in
[`docs/VERIFICATION.md`](docs/VERIFICATION.md).
