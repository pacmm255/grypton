# Migration from Krypton

The new active package is `grypton`, with version 2.0.0 and a `grypton` CLI.
Original code and documentation are preserved without modification in
`upstream/`. Original targets and session data were not inspected or migrated.
This is a source-only local fork with new Git history.

| Original behavior | Grypton behavior |
| --- | --- |
| Claude worker and Codex manager | GLM-5.3 worker and Muse Spark 1.3 Contributor manager via the requested OpenCode plans |
| Manager also provides validation | Dedicated Codex GPT-6 Astra max validator, independent of the worker assessment |
| Continuous hunt loop | Bounded review of supplied evidence, with completed checkpoints |
| Frozen and cloned Claude sessions | Explicit per-case evidence snapshots; no legacy session import |
| Target interaction and tool installation | Supplied-text analysis and remediation review |
| Unbounded blocker escalation | Deterministic local fixtures and explicit unresolved gaps |
| Terminal-only event stream | CLI plus responsive local dashboard with search and filters |
| Malformed ledger rows silently skipped | State corruption reported as an actionable error |
| Fixed temporary write filename | Unique temporary file, locking, and durable atomic replacement |
| Agent messages used as validation claims | Strict schemas and checks against actual evidence IDs |
| Relative prompt data outside package | Resources packaged inside the Python distribution |

The `target/` directory is deliberately empty. Grypton stores review state in
`.state/`, and excludes it from version control. There are no global shell,
OpenCode login, original project, or original executable changes.

Legacy `freeze`, target hunting, MCP attack tools, and autonomous account
provisioning are not exposed by the new application. Do not run the archived
launchers or archived live tests as part of Grypton. For the new supported
commands, use `./bin/grypton --help`.
