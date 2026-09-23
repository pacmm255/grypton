# Grypton verification

Verification covers the autonomous loop, selectable OpenClaude routes, tool
transport, credential isolation, scope enforcement, evidence integrity, Astra's
independent boundary, CLI review commands, and the dashboard.

These checks do not establish vulnerability-discovery accuracy on one host. The
mock integration test inserts predetermined findings and supplies a predetermined
confirmation. A passing audit proves workspace and control integrity; it does
not prove that Kraude found every issue. See
[`SINGLE_HOST_ACCURACY.md`](SINGLE_HOST_ACCURACY.md) for the evidence needed to
support an accuracy claim.

## Prerequisites

Real-backend checks expect:

- Node.js and OpenCode on `PATH`;
- OpenClaude at `/root/openclaude`, including `bin/openclaude.mjs` and
  `openclaude.config.json`;
- the Go provider configured with its private pool at `/root/open`;
- Codex available for direct Astra validation.

Never print or copy the key file during verification. Catalog discovery,
`doctor`, mock runs, syntax checks, and loopback gateway checks do not require a
paid model request.

## Automated checks

Run from `/root/grypton`:

```bash
python3 -m unittest discover -s tests -v
python3 tests/ui_smoke.py
python3 -m compileall -q grypton tests
node --check grypton/resources/openclaude_sidecar.mjs
git diff --check
./bin/grypton models --json
./bin/grypton doctor
```

The unit suite covers both `init` target forms, CLI model flags, per-engagement
model persistence, safe live-switch boundaries, fresh worker and manager
sessions after a switch, the immutable Astra route, the P1/P2-only automatic
validation gate, explicit lower-severity review, the mock
worker-manager-validator loop, multi-flow evidence handoff, OpenCode error
rendering, the 120-second MCP ceiling, scoped captures and replay, canonical URL
path subtrees and exclusions, explicit scheme/port binding, redirect blocking,
non-URL transport separation, direct and rendered credential login, large-response
preview limits, complete disk captures, report auditing, and CLI review
commands.

The rendered-login tests use a loopback single-page application and fake
credentials. Marker-mode acceptance requires one form submission for one
reserved attempt, a same-origin verification URL, an exact non-secret success
marker, and reusable cookie or bearer material. A fresh browser containing only
that material must receive the marker while a separate fresh anonymous browser
does not. Status-differential acceptance instead requires the configured exact
submission status, exact passively reached post-login URL, material created
before the live verification request, identical exact outcomes from live and
fresh persisted-session verification, and the configured exact 401/403 outcome
from a fresh anonymous browser. Verification redirects, wrong terminal URLs,
wrong login/live/replay/control statuses, duplicate or missing matching
submissions, and material created only by verification all fail. The verified
material must work through `authenticated_http_request`.
Tool results, captures, rendered HTML, response bodies, console messages, and
audit rows must omit the stored username, transformed username, password,
cookie, bearer token, and their encoded forms.

OpenClaude-facing tests must use fake routes, fake key sentinels, and loopback
upstreams. They must verify that provider configuration points only to the
local gateway, secrets are absent from configuration and sanitized events,
legacy `opencode-go/...` input becomes `go/...`, unavailable or tool-less
worker routes are rejected, and unsupported effort levels fail before a model
request. The suite also rejects a fixture primary key with HTTP 401, confirms
rotation to its spare, and confirms that the next request starts on the spare
without contacting a real provider.

The Playwright smoke test launches the loopback dashboard in Chrome, reads its
live JSON APIs, verifies the effective models saved for an engagement and the
independent finding verdict, checks tool and flow activity, exercises desktop
and mobile widths, and fails on browser errors.

The release wheel should also be built from a clean packaging tree and installed
in an isolated virtual environment. Acceptance requires the packaged prompts,
JSON schemas, scenarios, skills, dashboard assets, `openclaude.py`, and
`resources/openclaude_sidecar.mjs`; one mock orchestration turn must work from
the installed package, and the installed MCP entry point must expose the full
tool registry.

## OpenClaude acceptance checks

### Catalog and selection

These commands read the sanitized local catalog and do not start provider
inference:

```bash
./bin/grypton models glm
./bin/grypton models muse
./bin/grypton plan \
  --target http://127.0.0.1:18767 \
  --kraude-model zai-coding-plan/glm-5.3 \
  --kraude-effort max \
  --kryptex-model go/muse-spark-1.3-contributor \
  --kryptex-effort xhigh \
  -m "Verify model selection only"
```

Acceptance requires the chosen public routes and efforts to appear exactly as
selected. Kraude must be rejected if its route lacks tool support. The plan
must leave Astra at `gpt-6-astra` with `max` effort and automatic P1/P2 only.

### No-request gateway lifecycle

Starting and closing each role's gateway without sending a Messages request
must:

1. load OpenClaude from `/root/openclaude`;
2. bind only to loopback with a random port;
3. require the generated gateway token;
4. return the chosen public route and effective effort;
5. shut down its child process and listener cleanly;
6. leave provider quota untouched.

Use fake credentials for this check. Inspect only sanitized events; never put a
real key in an assertion, fixture, command line, or log.

### Key-pool rotation

Test key rotation with a fake loopback provider. Give the first fake key a
key-specific failure and let the second fake key return a small valid response.
The acceptance conditions are:

- one failed attempt with the first key and one successful attempt with the
  second;
- a sanitized notice naming only short fingerprints;
- the failed key remains benched on the next request;
- no raw fake key appears in stdout, stderr, OpenCode configuration, gateway
  events, provider-call records, or reports;
- the request is not replayed after any response stream begins.

Repeat classification checks for 401/402, qualifying quota or billing 403,
and qualifying spent-plan 429 results. Separately verify that connection
failures and HTTP 408, 425, and 5xx obey the configured retry window. Invalid
requests, unknown routes, unsupported effort, ordinary permission denials,
tool errors, and scope denials must not rotate keys.

## Optional live provider check

A live check consumes quota and should run only against an authorized local lab.
Start the bundled lab, choose the exact routes under review, and limit the run:

```bash
./bin/grypton lab --host 127.0.0.1 --port 18767

./bin/grypton init \
  --target http://127.0.0.1:18767 \
  --in-scope 127.0.0.1 \
  --kraude-model zai-coding-plan/glm-5.3 \
  --kraude-effort max \
  --kryptex-model go/muse-spark-1.3-contributor \
  --kryptex-effort xhigh \
  --max-turns 1 \
  -p \
  -m "Read the local page once, save the capture, and stop"
```

A successful check records one selected-route provider call through OpenClaude,
at least one scope-checked MCP call and flow capture, a Kryptex response through
its own selected route, clean child-process shutdown, and no credential text.
It does not demonstrate hunting accuracy or key rotation.

## Model-switch acceptance

During a local interactive run:

```text
❯ /model
❯ /models glm
❯ /model kraude zai-coding-plan/glm-5.3 max
❯ /model kryptex go/muse-spark-1.3-contributor xhigh
```

Each change must wait for a safe role boundary, validate against OpenClaude's
catalog, close the old role gateway, start a fresh provider session, update the
console header and model status, append `.ledger/model-switches.jsonl`, and save
the route and effort in engagement metadata. After stopping, `resume` must use
those saved values unless explicit run flags override them. Existing findings,
flows, scope, progress, and tested-technique records must remain intact.

## Astra boundary acceptance

For a mock or local-lab engagement, record candidates at different severities.
Acceptance requires:

- new P1 and P2 candidates automatically enter the Astra queue;
- P3, P4, and P5 remain `validation-not-requested`;
- `grypton validate ENGAGEMENT FINDING_ID` can explicitly request a lower-level
  review;
- every validator record names direct Codex `gpt-6-astra` at `max`;
- changing either OpenClaude role never changes validator configuration;
- no Kryptex output can supply or replace an Astra verdict.

## Monitored-run acceptance criteria

Finish an authorized engagement with:

```bash
./bin/grypton audit ENGAGEMENT
./bin/grypton findings ENGAGEMENT
./bin/grypton validate ENGAGEMENT FINDING_ID
./bin/grypton report ENGAGEMENT --output report.md
```

Acceptance requires the effective saved route and effort for each role, clean
OpenCode and OpenClaude exits, an Astra verdict for every non-suppressed P1/P2
finding, correct Astra provenance for explicitly reviewed P3-P5 findings, zero
structured scope violations, no missing canonical flow references, no secret
material in public outputs, and an empty `/root/grypton/target/` directory.
Tool-level negative results may remain in history when their error text is
preserved and Kraude or Kryptex handles them without unrequested route changes
or scope drift.
