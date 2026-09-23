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

A direct background `init` or `resume` must include `--duration`,
`--max-seconds`, or `--auto-stop-time`.

For a detached finite run, the deadline is the normal completion boundary.
Repeated convergence sends Kraude back through another Kryptex-directed pivot
instead of ending the run early. An operator stop or a binding scope/program
stop can still end it before the deadline.

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
