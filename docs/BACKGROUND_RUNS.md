# Durable background runs

Use Grypton's supervisor for a long engagement. It starts the engine in a
detached process group, writes a counter-only health event at the requested
interval, and stops at a finite deadline.

Create and start a 12-hour background engagement directly:

```bash
./bin/grypton init --target "https://app.example.test" --type web \
  --background --duration 12h --health-interval 10m --restart-limit 3
```

To supervise an existing engagement that is not currently running, use `run start`. It defaults to
12 hours when no duration option is supplied:

```bash
./bin/grypton run start https-app-example-test \
  --duration 12h --health-interval 10m --restart-limit 3
```

When Kraude needs a clean OpenCode conversation but the engagement evidence and
Kryptex operator-chat context should continue, add `--fresh-worker-session`:

```bash
./bin/grypton run start https-app-example-test \
  --fresh-worker-session --duration 12h
```

The same option works with foreground `resume`. It starts Kraude with the
current scope projection and the mission supplied to that resume. Findings,
attack-surface and tested-technique ledgers, workspace files, turn counters,
and Kryptex's saved operator-chat session remain in place. Autonomous Kryptex
directions already use one fresh, self-contained OpenCode session per turn. In
a detached run the option is a private one-shot setting: an engine restart
resumes the replacement Kraude session after its ID reaches durable metadata. If
the process fails before the first replacement turn completes, no resumable
session ID exists and the next engine child starts another clean Kraude conversation.
Grypton applies the same one-time worker-only reset when a saved engagement has
an older or missing worker prompt-contract version. It stores the current
version with the empty worker session ID, discards the old worker directive,
and preserves Kryptex's session and both saved model selections. The first
replacement turn uses the current resume mission or a narrow generic recovery;
later starts may resume the replacement worker and its current directive.

Long runs also roll Kraude into a fresh OpenCode conversation automatically when
the latest reported OpenCode context footprint reaches 250,000 tokens. Grypton
uses the final valid model step's explicit total when supplied; otherwise it
estimates the live context as uncached input, cache reads and writes, output,
and reasoning. This is a prospective next-call footprint, not cumulative billed
usage. Prior agentic steps and resumed calls are not summed because each later
input already contains the earlier conversation. Grypton persists the empty
worker session ID first, then continues with the same evidence, ledgers, model
selection, and Kryptex operator-chat session. The sanitized rollover event
records only the turn and context count. Set
`worker_context_rollover_tokens` in `grypton.json` to another positive integer,
or to `0` to disable automatic rollover. If a call has no valid usage record,
it does not cause a rollover.

A direct background `init` or `resume` must include `--duration`,
`--max-seconds`, or `--auto-stop-time`.

For a detached finite run, the deadline is the normal completion boundary.
Repeated convergence sends Kraude back through another Kryptex-directed pivot
instead of ending the run early. The opening mission remains verbatim; later
soft-stop recovery selects a positive highest-impact unresolved action rather than
replaying a completed login or setup task. An operator stop or a binding
scope/program stop can still end it before the deadline.

If OpenClaude reports that every Kraude credential is temporarily exhausted,
deadline mode keeps the engagement alive. It waits for the sanitized provider
cooldown, capped at five minutes per wait. Exact replay is allowed only when the
provider positively reports that OpenCode never started. Once the native-capable
OpenCode process exists, Grypton treats any failure as execution-uncertain even
when no tool event reached stdout. It persists an empty Kraude session ID and
continues from durable evidence with a different positive action so a completed
operation is not replayed after an unflushed event.
Failed provider attempts do not advance the completed-turn counter or consume
`--max-turns`, and five consecutive cooldowns do not become a clean engine stop.
The wait checks the run deadline, the external stop file, and an operator stop at
least once per second. Errors without that structured transient classification
still follow the finite fault path, and programming or configuration failures
exit as failures.

Check and stop the run without `nohup`, `tee`, or a terminal multiplexer:

```bash
./bin/grypton run status https-app-example-test
./bin/grypton run logs https-app-example-test --limit 30
./bin/grypton run stop https-app-example-test
```

The lifecycle log contains timestamps, process IDs, exit codes, and workspace
counters. It never contains the mission, prompts, tool arguments, evidence,
credentials, or provider output. Full evidence remains in the engagement's
private workspace. Supervisor directories use mode `0700`; specs, state, PID
files, and event logs use mode `0600`.

Before a network, process, installer, or workspace-mutating MCP handler begins,
Grypton fsyncs an argument-free marker to the engagement ledger. The supervisor
retries only an abnormal engine exit before any such marker, up to
`--restart-limit`. Private read-only calls do not set the marker. It never
restarts a clean exit, a persisted scope or policy stop, an operator stop, or
an abnormal exit after an effectful tool began. A background start is rejected
while the engagement's shared engine lock is held by a foreground run.
