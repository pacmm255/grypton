# Grypton architecture

Grypton is an evidence-review application derived from Krypton's role separation
and locked-state design. The original application is archived in `upstream/`;
the installed package is only `grypton`.

```text
Krypton-style terminal / CLI / loopback dashboard
          |
      Engagement store <---------- conversation, standing instructions,
          |                        checkpoints, evidence hashes, review events
          |
          +--> live chat: operator → Kryptex → immediate task kickoff to Kraude
          |
      Finite review engine
          |
          +--> Kryptex / OpenCode Go / Muse Spark 1.3 Contributor xhigh
          |       Structured review checklist and local requirements
          |
          +--> Kraude / Z.AI Coding Plan / GLM-5.3 max
          |       Evidence assessment and remediation
          |       At most one follow-up for a new local capability
          |
          +--> Codex / GPT-6 Astra max
          |       Independent claim + original evidence only
          |       Checked verdict, severity, evidence IDs, limitations
          |
          +--> Kryptex
                  Summary preserving the validator's conclusion

      Finding ledger validation
          |
          +--> Kryptex plan → Astra (claim + selected evidence only)
          |                     → Kryptex summary
          +--> versioned verdict history and per-call audit digests
```

`init <target>` and `init --target <target>` create the same stable engagement,
seed its in-scope labels, and open the console when attached to a TTY. `resume`
resolves an ID, target, title, or unique prefix. Task directives are stored before
the manager call and delegated to Kraude for a concrete kickoff. Conversation,
standing instructions, observations, scope, surface records, and findings survive
console restarts. The independent validator receives only the original claim and
immutable evidence snapshots.

All model calls are text-only. Agent tool permissions and execution features are
disabled. The application has no API for probing targets, installing tools,
reproducing exploits, creating accounts, or treating model output as executable
commands. The original hunt engine is never imported by the new package.

## State and recovery

Each case has a versioned private `case.json` under `.state/cases/<id>/`. Evidence snapshots
contain text, original basename, artifact ID, SHA-256, and import time. A case
contains up to 100 review runs plus scope, messages, standing instructions,
observations, surface records, findings, and local-resource events. Each run
records model routes, backend mode, context digest, role-prompt fingerprints,
stage checkpoints, resources, progress events, and per-call SHA-256 audit data.

A process-level file lock serializes record access. Atomic writes use unique
temporary files, fsync, replace, and directory fsync. A separate nonblocking
review lock prevents simultaneous runs and evidence edits for one case. Invalid
state is reported explicitly. Resume validates the input digest and model routes
before reusing any result. New evidence makes the previous verdict historical.

Provider calls have bounded time and output. Cancellation and timeout terminate
the process group, including descendants whose parent has already exited. A stop
marker is checked while the active call runs. Process crashes leave completed
checkpoints available to a subsequent `resume`.

## Output contracts

Each role has a fixed JSON schema. Extra fields, duplicate keys, invalid values,
unknown evidence IDs, and unsupported severity claims are rejected. A model
cannot mark its own output as independently validated. The manager's closing
response has only summary and next-step fields; it cannot overwrite Codex's
structured verdict. Provider errors are failures even if the CLI returns zero.

## Modules

| Module | Responsibility |
| --- | --- |
| `config.py` | Exact model routes, resources, workspace selection |
| `storage.py` | Private case records, locks, snapshots, bounded imports |
| `contracts.py` | Structured output validation and evidence-reference checks |
| `backends.py` | Isolated OpenCode, ephemeral Codex, process cleanup, mock transport |
| `engine.py` | Finite stage order, checkpoint/resume, local requirements |
| `integrity.py` | Read-only routes, assets, snapshot, source-inventory, and credential audit |
| `lab.py` / `lab_runner.py` | Fixed evidence-transition scoring and isolated pipeline runs |
| `console.py` | Persistent terminal chat, slash commands, manager-to-worker relay, role consoles |
| `doctor.py` | Read-only binary, authentication, and model-readiness checks |
| `presentation.py` | Public projections, terminal output, Markdown reports |
| `cli.py` | Target-first engagement operations and predictable CLI behavior |
| `web.py` | Read-only loopback HTTP server with a route allowlist |
| `resources/` | Model registry, prompts, skills, scenarios, dashboard assets |

Provider isolation depends on the installed CLI honoring its configuration.
Read-only sandboxing alone does not imply that a model cannot read host data;
the explicit tool disabling and supplied-text workflow are essential here.
