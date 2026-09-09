# Differences from Krypton

The current `grypton` package is a separate evidence-review application. A
behavior-compatible migration from Krypton has not been completed. The table
below describes workflow changes, not evidence that the requested improvements
or equivalent accuracy were delivered. See [the source audit](KRYPTON_PARITY_AUDIT.md).

The active package has version 2.1.0 and a `grypton` CLI. A selection of 28
original code and documentation files is preserved without modification in
`upstream/`; 11 tracked source/helper files were omitted. Original targets and
session data were not inspected or migrated. This checkout has new Git history.

| Original behavior | Grypton behavior |
| --- | --- |
| Claude worker and Codex manager | GLM-5.3 worker and Muse Spark 1.3 Contributor manager via the requested OpenCode plans |
| Main loop records manager-directive verdicts; a separate Codex-first validation method exists | Dedicated Codex GPT-6 Astra max validator, independent of the worker assessment |
| `init <target> [-m brief]` starts the terminal | Both `init <target>` and `init --target <target>` open the persistent console; `--claim` is optional and the target seeds scope |
| User talks to manager; `/worker` routes directly | Task directives are persisted before interpretation; Muse/Kryptex delegates a no-evidence kickoff immediately to GLM/Kraude; `/worker` remains available |
| Continuous hunt loop | Persistent conversation plus an explicit bounded review sequence with completed checkpoints |
| Frozen and cloned Claude sessions | Explicit per-case evidence snapshots; no legacy session import |
| Target interaction and tool installation | Supplied-text analysis and remediation review |
| Unbounded blocker escalation | Up to three chat turns resolve sequential local email, identity, text-fixture, evidence, and scratch requirements; external gaps remain explicit |
| Terminal event stream | Slash-command console with bracketed paste, scope, history, observations, surface, finding validation, resources, and a responsive operations dashboard |
| Malformed ledger rows silently skipped | State corruption reported as an actionable error |
| Fixed temporary write filename | Unique temporary file, locking, and durable atomic replacement |
| Agent messages used as validation claims | Strict schemas and checks against actual evidence IDs |
| Relative prompt data outside package | Resources packaged inside the Python distribution |
| No fixed accuracy corpus | Three-scenario, nine-transition synthetic lab with deterministic 13-component scoring and direct run/score round trips |
| Manual source comparison | `grypton audit` verifies routes, assets, exclusions, snapshot hashes, and the recorded source inventory |

The `target/` directory is deliberately empty. Grypton stores review state in
`.state/`, and excludes it from version control. There are no global shell,
OpenCode login, original project, or original executable changes.

Legacy `freeze`, target hunting, MCP attack tools, and autonomous account
provisioning are not exposed by the new application. Source launchers now exist
for `grypton`, `kraude`, and `kryptex`; they are new constrained adapters, not
copies of the original launchers. Do not run the archived live tests as part of
Grypton. For supported commands, use `./bin/grypton --help`.
