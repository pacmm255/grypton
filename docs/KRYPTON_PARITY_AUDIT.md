# Krypton compatibility audit

Inspected on 2026-09-09. The initial Grypton fork implemented a different
application and did not preserve the working Krypton workflow. The follow-up
changes restore the target-first console, persistent instructions, role routing,
and model coordination described below. Grypton still uses a supplied-material
review boundary, so matching model names and passing these tests do not establish
full runtime compatibility or equal finding accuracy.

## Inspection scope

The source inventory covers 39 tracked project files, totaling 10,173 lines,
from the original working tree at `/root/krypton`. Its Git revision is
`3ce1cd003feb07593d4f4b5e89fe11858837bb9b`; the inventory hashes the actual working
files rather than assuming the revision contains every local change.

The CLI, terminal interaction, worker/session lifecycle, manager calls,
workspace storage, prompt composition, tool interfaces, and validation paths
were traced statically. All 25 Python files/launchers were parsed without
importing or executing Krypton. The three JSON schemas were parsed. Both shell
helpers received syntax checks. All 38 functions named `test_*` in the original
offline suite were indexed along with their literal check labels; selected test
bodies and both live-test scripts were read. The binary patch helper and batch
launcher were inspected structurally, without executing them. This is a
compatibility and architecture review, not exhaustive runtime or security
verification of every branch.

The [file inventory](verification/krypton-source-audit.json) records paths,
line counts, hashes, and snapshot inclusion. The original target directories,
session histories, runtime state, credentials, and untracked engagement
artifacts were excluded. No original module, launcher, installer, model call,
or live test was executed during this audit.

## What Krypton actually does

The terminal is the front end of a continuing application, with durable shared
state and concurrent user interaction. Its behavior is spread across the
engine, adapters, workspace, prompts, and launchers; changing the CLI alone
cannot preserve that behavior.

| Contract | Original implementation | Current Grypton |
| --- | --- | --- |
| Initialize | `cmd_init` accepts a target and optional `-m/--brief`, prepares state, and starts terminal interaction. There is no `--claim` requirement. | Accepts positional and `--target` forms, reuses an existing matching engagement, seeds scope, and opens the console on a TTY. `--claim` remains optional. |
| No arguments | The original parser requires a subcommand. | Displays the evidence-review case list. The original did not have the proposed no-argument chat either. |
| Resume | Reuses workspace metadata, worker identity, manager session, and prior directive. | Reopens persistent conversation and can resume completed finite-review checkpoints. It does not resume one long-lived provider process. |
| Worker continuity | The Claude adapter maintains a bidirectional streaming process and resumes the same session after restart. The alternate Codex worker resumes a thread across subprocess calls. | Persists bounded conversation and sends it with isolated OpenCode calls; provider-process continuity is not restored. |
| Manager interaction | User-to-manager chat runs concurrently with worker activity. Normal text goes to the manager; `/worker` routes a message to the worker. | Normal text goes to Kryptex, `apply-now` relays to Kraude, and `/worker` routes directly. Calls are sequential rather than concurrent with a hunt loop. |
| Remembered instructions | Verbatim user instructions are persisted before manager interpretation and reappear in subsequent context. | Task directives are persisted before manager interpretation; manager-selected instructions and all conversation messages also survive resume. |
| Workspace | JSONL records track findings, observations, and prior attempts; Markdown logs preserve manual additions across resume. | Versioned `.state/cases/` records hold scope, claims, immutable text snapshots, messages, observations, surface entries, findings, stages, resources, and call audits. |
| Terminal visibility | Streams worker activity, tool events/results, manager replies, directives, findings, verdicts, and periodic progress. Includes paste handling and stop-intent parsing. | Shows routes, manager/worker replies, resources, stages, artifacts, findings, and verdicts. Bracketed multiline paste and stop handling are restored; a background hunt-event stream is not. |
| Launchers | Repository launchers expose the application, actual worker/manager CLI wrappers, full MCP/CLI tools, and an advisor server. | Source and installed `grypton`, `kraude`, and `kryptex` launchers are functional constrained adapters. The original MCP/tool/advisor launchers remain excluded. |
| Runtime settings | Model/manager choices persist in workspace metadata and can be changed during a session. | Model routes are fixed for the staged review and checked when resuming it. |
| Prompts and guidance | Editable worker/manager templates, generated workspace context, JSON output schemas, and advisor command/context templates are integrated with the running application. | Role prompt bundles integrate eight packaged skills, workspace context, strict schemas, and stored SHA-256 provenance. Three nine-turn transition scenarios exercise them. |
| Tools and records | A registry of 14 tools shares handlers between MCP and CLI interfaces, including structured workspace operations. | Model tool execution is disabled; attached text is the input boundary. |

Key source locations:

- [CLI initialization and startup](/root/krypton/krypton/cli.py:160) and
  [parser](/root/krypton/krypton/cli.py:417).
- [Terminal renderer](/root/krypton/krypton/chat.py:129),
  [interaction](/root/krypton/krypton/chat.py:322),
  [input routing](/root/krypton/krypton/chat.py:351), and
  [concurrent manager conversation](/root/krypton/krypton/engine.py:815).
- [Worker session adapter](/root/krypton/krypton/worker.py:83),
  [snapshot/clone implementation](/root/krypton/krypton/sessions.py:269), and
  [manager context construction](/root/krypton/krypton/engine.py:558).
- [Workspace metadata](/root/krypton/krypton/workspace.py:192),
  [persistent instructions](/root/krypton/krypton/workspace.py:284),
  [append-only documents](/root/krypton/krypton/workspace.py:389), and
  [tool registry](/root/krypton/krypton/toolserver.py:321).

The original manager receives bounded summaries and can access workspace files;
the documentation's claim of seeing everything should not be read as unlimited
prompt context. The Claude seed is stored conversation context, not evidence
that the underlying model was fine-tuned. That session data was not inspected
or transferred, and its contribution to prior results was not measured.

## Validation and accuracy observations

These observations come from source inspection. They are not measured claims
about historical findings or comparisons between Claude, GLM, Muse, and Astra.

1. **A separate Codex validation pass is not guaranteed by the normal loop.**
   [KryptexManager.validate_severity](/root/krypton/krypton/manager.py:862)
   implements a Codex-first validation route. However, the normal engine does
   not call that method. It writes verdicts from
   [the manager's directive](/root/krypton/krypton/engine.py:591). The source
   search found explicit calls to the separate method in tests, not in the
   application loop. The function's existence and its direct unit checks do
   not prove that every finding receives a dedicated validator call.

2. **The P1 counter can count an unvalidated claim.**
   [confirmed_p1s](/root/krypton/krypton/workspace.py:318) falls back to the
   worker's severity when no manager severity exists and accepts a missing
   verdict. It also does not filter the finding's scope-suppression status.
   Consequently, the name “confirmed P1s” promises more than the predicate
   establishes. This observation does not establish whether that happened in
   any actual workspace.

3. **Verdict deduplication can suppress a changed judgment.**
   [The redundancy predicate](/root/krypton/krypton/engine.py:607) checks an
   existing decisive verdict and whether the severity changes. It does not
   compare the new verdict's meaning. An incoming rejection or request for
   more evidence at the same severity can therefore be skipped after an
   earlier confirmation. The existing deduplication tests cover repeated
   confirmations and severity changes, without establishing this transition.

4. **Some original documentation describes older behavior.**
   The [source defaults](/root/krypton/krypton/config.py:67) are
   `claude-sonnet-5` / `high`, while README and prompt headings still mention
   Opus 4.8 / max. Runtime environment and workspace overrides can differ
   again; those were not inspected. Architecture prose describes regenerated
   Markdown views, while the current implementation preserves append-only
   documents. Documentation also describes manager boundary stops that the
   current engine overrides. The working code, tests, and documentation need
   to be distinguished when describing the baseline.

The replacement's independent validator judges whether supplied text supports
a stated claim. That is a different task from Krypton's workflow and severity
assessment. Success on a synthetic configuration claim cannot establish
equivalent discovery, reproduction, evidence completeness, or severity accuracy.

## What was omitted from the fork

The 28 files in `upstream/` are an inactive selected snapshot, not the active
implementation. Their hashes match the fork manifest and original source.
Eleven tracked files were omitted:

- `bin/krypton`, `bin/kraude`, `bin/kryptex`.
- `bin/krypton-mcp`, `bin/krypton-tool`, `bin/advise-mcp`.
- `bin/.claude-fable-unlock.py`.
- `dotfiles/claude/CLAUDE.md`, `dotfiles/claude/commands/advisor.md`,
  `dotfiles/install-advisor.sh`.
- `launch_20.sh`.

Listing these files documents the incomplete source selection. It does not
mean their binary-patching, refusal-rewriting, or operational behavior was
executed, ported, or approved by this audit.

## What the earlier tests established

The current 56 passing Grypton tests cover the case store, provider isolation,
text-review contracts, finite checkpoints, local fixtures, and HTTP dashboard.
The browser checks covered that new dashboard. The live checks established
that synthetic requests could reach the configured model routes and complete
the new review sequence. Those results remain scoped to that application.

Krypton's offline suite contains 38 `test_*` functions, using a custom `check`
helper with multiple checks per function. Its contracts include session
isolation, terminal routing/paste handling, persistent instructions, model
changes, event translation, append-only records, and tool interfaces. Those
contracts were not carried into Grypton's acceptance tests. Neither a count
of test functions nor the original mock finding labels is an accuracy metric.
The original live scripts check connectivity, session continuity, and basic
orchestration; they are not comparative accuracy benchmarks.

UI and state compatibility require tests against the original user-visible
contracts. A claim of equal finding accuracy additionally requires a defined
ground-truth corpus, consistent inputs, and measured verdict errors. No such
comparison was performed, and this audit does not claim that any requested
model is more or less accurate.

## Result of this audit

After the audit, the active application gained both target initialization forms,
automatic scope seeding, persistent directives, guaranteed task kickoff,
manager-to-worker relay, bracketed paste, expanded slash commands, durable scope,
surface and finding records, direct Astra validation, per-call audit metadata,
an integrity dashboard, and a fixed transition lab. README, migration notes, and
the verification report identify the remaining compatibility gap explicitly.
Original source and the preserved snapshot were left unchanged; existing
Grypton case data was not edited by the migration. The autonomous runtime
migration remains incomplete; the new console does not claim to restore that
execution behavior or establish equal finding accuracy.
