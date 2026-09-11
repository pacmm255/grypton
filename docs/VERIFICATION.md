# Grypton verification

Verification covers the autonomous loop, exact model routing, tool transport,
scope enforcement, evidence integrity, CLI review commands, and dashboard.

These checks do not establish vulnerability-discovery accuracy on a single
host. The mock integration test inserts predetermined findings and supplies a
predetermined confirmation. Neither a passing audit nor a zero-finding run
measures missed findings. Single-host precision, recall, and the accuracy impact
of the convergence changes remain unmeasured. See
[`SINGLE_HOST_ACCURACY.md`](SINGLE_HOST_ACCURACY.md) for the source-level review
and the evidence required to support an accuracy claim.

## Automated checks

Run from `/root/grypton`:

```bash
python3 -m pytest -q
python3 tests/ui_smoke.py
python3 -m compileall -q grypton tests
git diff --check
./bin/grypton doctor
```

The unit suite covers both `init` target forms, exact route pins, clean CLI
shutdown, the P1/P2-only automatic validation gate, explicit lower-severity
review, the mock worker-manager-validator loop, Spark/Astra separation,
multi-flow evidence handoff, OpenCode error rendering, the 120-second MCP
ceiling, scoped captures and replay, explicit port binding, redirect blocking,
large-response preview limits, complete disk captures, report auditing, and CLI
review commands.

The Playwright smoke test launches the loopback dashboard in Chrome, reads its
live JSON APIs, verifies all three model cards and the independent finding
verdict, checks tool and flow activity, exercises desktop and mobile widths, and
fails on browser errors.

The release wheel is also built from a clean packaging tree and installed into
an isolated virtual environment. Acceptance checks require the packaged prompts,
JSON schemas, scenarios, skills, and dashboard assets; reject stale legacy
modules; run one mock orchestration turn; and verify the installed MCP entry
point exposes all 27 tools.

## Live provider checks

The exact worker route has been exercised through OpenCode with a real Grypton
MCP call. A delayed loopback endpoint waited 12 seconds; GLM 5.3 max made exactly
one `grypton_http_request`, completed successfully after the old ten-second
failure point, and returned the expected response marker. This verifies that a
newly loaded process uses the 120-second MCP ceiling.

A separate local integration engagement ran the persistent GLM → Spark → Astra
cycle for three turns against the instrumented loopback target. It produced
real scoped captures, manager directives, independent verdicts, and durable
ledgers without contacting an external host.

## Monitored-run acceptance criteria

For a real engagement, finish with:

```bash
./bin/grypton audit ENGAGEMENT
./bin/grypton findings ENGAGEMENT
./bin/grypton validate ENGAGEMENT FINDING_ID
./bin/grypton report ENGAGEMENT --output report.md
```

Acceptance requires exact route and effort pairs, zero provider exit failures,
an Astra verdict for every non-suppressed P1/P2 finding, correct Astra provenance
for explicitly reviewed P3–P5 findings, zero structured scope violations, no
missing canonical flow references, and an empty `/root/grypton/target/` directory.
Tool-level negative results may remain in the history when their error text is
preserved and the worker handles them without route fallback or scope drift.
