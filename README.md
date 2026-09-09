# Grypton

A local workspace for reviewing **supplied security evidence and remediation**.
Kryptex coordinates Kraude, and Codex independently validates the claim against
the evidence. Reviews are finite, checkpointed, and visible in a CLI and browser
dashboard.

**Compatibility status:** Grypton now restores Krypton's target-first
`init`/`resume` flow, persistent terminal conversation, manager-to-worker relay,
standalone role launchers, and familiar slash commands. Its execution boundary
is still a supplied-material review rather than Krypton's autonomous live-target
engine. Passing tests do not establish equal finding accuracy. See the
[source comparison](docs/KRYPTON_PARITY_AUDIT.md).

A snapshot of 28 selected source files from `/root/krypton` is retained in
[`upstream/`](upstream/) for provenance. The installed
Grypton application does not import or launch the archived hunt engine, network
tools, installers, or account workflows. It does not reproduce exploits or
autonomously interact with targets.

## Models

| Role | Runner / plan | Model | Reasoning |
| --- | --- | --- | --- |
| Kraude, worker | OpenCode / Z.AI Coding Plan | `zai-coding-plan/glm-5.3` | `max` |
| Kryptex, manager | OpenCode / Go | `opencode-go/muse-spark-1.3-contributor` | `xhigh` |
| Independent validator | Codex | `gpt-6-astra` | `max` |

The exact routes are packaged in
[`grypton/resources/models.json`](grypton/resources/models.json). There is no
automatic fallback to another model, effort, or billing plan. `doctor` verifies
the installed model catalogs and credentials; it does not spend model tokens.

Muse Spark 1.3 is listed on Go as **Contributor**. That offering permits model
training on submitted prompts and completions and is not a zero-retention
offering. A live review sends attached evidence to the configured providers.
Go's API URL contains `/zen/go/v1`; that is the Go endpoint, separate from the
regular Zen endpoint. See the [OpenCode Go documentation](https://opencode.ai/docs/go/).
The validator's `max` setting is supported by
[GPT-6 Astra](https://developers.openai.com/api/docs/models/gpt-6-astra).

## Start

Python 3.11+ is required. Grypton itself has no third-party runtime dependencies.
From this checkout:

```sh
cd /root/grypton
./bin/grypton doctor
./bin/grypton audit --auth
./bin/grypton init --target "project.example" -m "Review the supplied authorization evidence"
./bin/grypton resume project-example
./bin/grypton serve
```

`init TARGET` and `init --target TARGET` are equivalent, and neither requires
`--claim`. Initialization records the target as the first in-scope label and
opens the terminal console on a TTY. A task directive such as `pentest
project.example` is remembered before model interpretation. Kryptex immediately
delegates a useful kickoff to Kraude, even when no artifacts are attached, and
does not ask the operator to repeat the stored target, claim, scope, or brief.
If the manager returns a passive refusal for a task directive, the console
replaces it with a concrete accepted-work kickoff and still performs the Kraude
delegation.

The console supports `/worker`, `/evidence`, `/review`, `/finding add`,
`/validate`, `/findings`, `/note`, `/surface`, `/brief`, `/claim`, `/scope`,
`/history`, `/instructions`, `/resources`, `/status`, `/models`, `/help`, and
`/stop`. Bracketed multiline paste is preserved as one instruction. Use `--mock`
for an offline conversation or `--no-interact` for scripting.

Open `http://127.0.0.1:8765`. The dashboard is local and read-only; it shows model
routes, scope, observations, surface records, finding history, per-call audit
metadata, requirements, independent verdicts, fork integrity, and the fixed
validation lab. Screenshots from synthetic browser checks:
[desktop](docs/verification/dashboard-desktop.png) and
[mobile](docs/verification/dashboard-mobile.png).

The source launcher works from any directory. An isolated installation is also
available through `.venv/bin/grypton` after installation:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/grypton --help
```

Installed console entry points are `grypton`, `kraude`, and `kryptex`. The source
checkout also has all three launchers in `bin/`. `kraude` opens the requested
GLM role and `kryptex` opens the requested Muse role; both use isolated OpenCode
state and denied tool permissions. A message can be supplied as arguments or on
stdin, and `--mock` is available for offline checks.
Use `--root /path/to/workspace` or `GRYPTON_ROOT` to choose another state directory.
A wheel installation defaults to the working directory; the checkout launcher
defaults to this fork.

## Review supplied material

```sh
./bin/grypton init "cookie-service" -m "Check whether secure cookies are explicitly enabled"
./bin/grypton evidence add cookie-service /path/to/owner-supplied-evidence.txt
./bin/grypton review cookie-service --dry-run
./bin/grypton review cookie-service
./bin/grypton show cookie-service
./bin/grypton report cookie-service
```

Scope and durable workspace records can also be managed without entering the
console:

```sh
./bin/grypton scope set cookie-service --type web --in-scope cookie-service --rule "Use owner-supplied artifacts"
./bin/grypton note cookie-service "Release 2026.09 is the version under review."
./bin/grypton surface add cookie-service route /account
./bin/grypton findings add cookie-service "The supplied configuration omits the required control."
./bin/grypton findings validate cookie-service finding-0001
./bin/grypton history cookie-service
```

The stable engagement ID is derived from the target. Existing records made by
the earlier case CLI are resolved by target/title when unambiguous. Evidence is
imported as a private, immutable
text snapshot with a SHA-256 digest. Import reads only the specific file named;
it does not crawl directories. Evidence limits are 16 UTF-8 files, 160,000 bytes
per file, and 600,000 bytes total. Original-project paths, `targets` paths,
symlinks, devices, binary files, and empty files are rejected.

`review --mock` is offline. Mock verdicts are always inconclusive and marked
MOCK in the dashboard and reports. `demo --scenario NAME` creates a synthetic
offline example. `scenarios` lists configuration, contradictory evidence,
missing context, remediation, and offline email examples.

The manager plans, the worker assesses, Codex independently validates, and the
manager summarizes. At most one additional worker call can follow a newly
resolved local requirement, for a maximum of five model calls per review.
Codex receives the original claim and evidence without the worker's conclusion.
Only its checked response supplies the independent verdict and severity.
`supported` means the supplied evidence supports the stated claim; it does not
mean the finding was reproduced on a live system.

Every complete review creates a finding-ledger record. A manually added finding
uses a separate three-stage path: Kryptex plans, GPT-6 Astra receives only that
finding's claim and selected evidence, and Kryptex summarizes the independent
verdict. Context changes mark prior conclusions outdated. Each provider call
records its role, exact route, duration, status, and input/prompt/output digests;
raw prompts are not stored.

## Regression lab and self-audit

```sh
./bin/grypton lab list
./bin/grypton lab verify
./bin/grypton lab run --mock --save /tmp/grypton-lab.json
./bin/grypton lab score /tmp/grypton-lab.json
./bin/grypton audit --auth
```

The lab contains three fixed scenarios with nine ordered evidence transitions.
It checks structured contracts, citations, outcome changes, severity discipline,
grounding, remediation, validator isolation, bounded calls, and hallucination
guards. Saved `lab run` output can be passed directly to `lab score`.

`audit` is read-only. It verifies exact routes, validator isolation, prompt
fingerprints, eight skills, lab and dashboard assets, launchers, package version,
the empty `target/` directory, the 28-file preserved snapshot, and the recorded
39-file original-source inventory. `--auth` checks both OpenCode connectors and
the supplied Go key match without displaying credential values. It never opens
target, session, or runtime data and makes no model calls.

## Stop, resume, and inspect

```sh
./bin/grypton stop CASE_ID
./bin/grypton resume CASE_ID
./bin/grypton resume CASE_ID --mock
./bin/grypton resume CASE_ID --review
./bin/grypton show CASE_ID --json
./bin/grypton show CASE_ID --evidence
./bin/grypton evidence list CASE_ID
./bin/grypton status --json
```

`resume` reopens the persistent terminal conversation. Use `resume --review` or
`review --resume` to continue an interrupted model sequence. Ctrl-C or `stop`
interrupts the current provider call and terminates its process group. Completed
stages are checkpointed and require unchanged evidence, backend mode, and model
routes before reuse. Adding evidence marks the prior verdict as outdated. Model errors,
invalid JSON, unknown evidence references, missing credentials, and timeouts
produce explicit failures instead of invented results or automatic fallbacks.

The per-call timeout defaults to 600 seconds; use `--timeout SECONDS` between
1 and 3600. High reasoning settings can take several minutes. Provider usage,
quotas, and availability remain controlled by the respective plans.

`--json` works before or after subcommands. A command emits one JSON result on
stdout, with progress on stderr. Errors return status 1; parser errors return 2;
interruption returns 130. The CLI avoids emitting model reasoning traces.

## Local requirements

Kryptex can reuse supplied evidence, allocate a private scratch directory, and
provide explicitly synthetic `.invalid` email, offline identity, and temporary
text fixtures without operator interaction. It can resolve sequential local
requests and returns them to the requesting role in the same console operation.
It records unavailable resources and continues independent review work. It
cannot impersonate you, create real accounts, obtain external identities, buy
services, expand scope, or bypass access controls. Missing evidence remains a
stated limitation. See the packaged
[blocker-handling skill](grypton/resources/skills/blocker-handling.md).

## Credentials and data

Grypton uses the installed OpenCode `zai-coding-plan` and `opencode-go`
credentials. On this machine, the installed Go key was checked against the
provided `/root/open` file. Grypton verifies that match when the file exists.
It copies only the active role's key into private temporary OpenCode state and
removes that state after the call. It does not modify the global OpenCode login,
copy keys into the repository, rotate keys, or activate another plan.

OpenCode runs with isolated XDG configuration and data, external plugins
disabled, sharing disabled, and all agent tool permissions denied. Codex runs
ephemerally with user config and exec rules ignored, a read-only sandbox,
network search disabled, and shell, app, plugin, computer-use, and delegation
features disabled. The model inputs are explicit text snapshots, never an
autonomous target workspace. The subprocess adapters are not a security boundary
against a compromised provider CLI or a hostile local OS user.

Case state lives under `.state/cases/`, outside the empty `target/` directory.
State files use restrictive permissions, locked access, atomic replacement, and
durable writes. Back up `.state` if you want to retain review history. The HTTP
server binds only to `127.0.0.1`, exposes an explicit route allowlist, checks Host
and Origin, and has no write API. It does not require a password; local processes
on the same host can access it. Model-generated text is rendered as text.

## Development and provenance

```sh
python3 -m unittest discover -s tests -v
python3 tests/ui_smoke.py
python3 -m build --wheel
```

The standard test suite is offline. The optional browser check requires
Playwright and `/usr/bin/google-chrome` and uses synthetic temporary state.
Only run tests in `tests/`; `upstream/tests/` is an archived suite for the old
application and is not part of Grypton validation.

[`FORK_MANIFEST.json`](FORK_MANIFEST.json) records the original revision and hashes
of the 28 copied source files. The snapshot represents source files as found in
the working tree, including any preexisting local edits. No original target
directory, session, runtime artifact, tool download, credential file, or Git
history was read for copying or included in the snapshot. `target/` was created
empty; Git cannot track empty directories, so recreate it after another clone.

The original `pyproject.toml` declares its license **Proprietary**, despite the
project being described as open source in the request. The snapshot and package
metadata retain that declaration and the original attribution. No new
open-source license or permission to redistribute has been asserted.

See [architecture](ARCHITECTURE.md), [migration notes](docs/MIGRATION.md), the
[requested-change checklist](docs/REQUEST_CHECKLIST.md), and
[verification](docs/VERIFICATION.md) for implementation and validation details.
