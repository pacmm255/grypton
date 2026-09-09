# Grypton

A local workspace for reviewing **supplied security evidence and remediation**.
Kryptex coordinates Kraude, and Codex independently validates the claim against
the evidence. Reviews are finite, checkpointed, and visible in a CLI and browser
dashboard.

This is a defensive fork of the source in `/root/krypton`. The original source
snapshot is retained in [`upstream/`](upstream/) for provenance. The installed
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
./bin/grypton models
./bin/grypton demo
./bin/grypton serve
```

Open `http://127.0.0.1:8765`. The dashboard is local and read-only; it shows model
routes, case search, status filtering, artifacts, review progress, requirements,
and independent verdicts. Screenshots from synthetic browser checks:
[desktop](docs/verification/dashboard-desktop.png) and
[mobile](docs/verification/dashboard-mobile.png).

The source launcher works from any directory. An isolated installation is also
available through `.venv/bin/grypton` after installation:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/grypton --help
```

Installed console entry points are `grypton`, `kraude`, and `kryptex`. `kraude`
points operators to the coordinated review workflow; `kryptex` exposes the same
case CLI. These entry points do not replace your original project's executables.
Use `--root /path/to/workspace` or `GRYPTON_ROOT` to choose another state directory.
A wheel installation defaults to the working directory; the checkout launcher
defaults to this fork.

## Review a claim

```sh
./bin/grypton init "Cookie configuration review" --claim "The supplied configuration explicitly enables secure cookies."
./bin/grypton evidence add CASE_ID /path/to/owner-supplied-evidence.txt
./bin/grypton review CASE_ID --dry-run
./bin/grypton review CASE_ID
./bin/grypton show CASE_ID
./bin/grypton report CASE_ID
```

Use the case ID returned by `init`. Evidence is imported as a private, immutable
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

## Stop, resume, and inspect

```sh
./bin/grypton stop CASE_ID
./bin/grypton resume CASE_ID
./bin/grypton resume CASE_ID --mock
./bin/grypton show CASE_ID --json
./bin/grypton show CASE_ID --evidence
./bin/grypton evidence list CASE_ID
./bin/grypton status --json
```

Ctrl-C or `stop` interrupts the current provider call and terminates its process
group. Completed stages are checkpointed. `resume` requires unchanged evidence,
backend mode, and model routes, and skips completed stages. Use `review` for a
fresh run. Adding evidence marks the prior verdict as outdated. Model errors,
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
provide an explicitly synthetic `.invalid` email fixture without operator
interaction. It records unavailable resources and continues independent review
work. It cannot impersonate you, create real accounts, obtain external
identities, buy services, expand scope, or bypass access controls. Missing
evidence remains a stated limitation. See the packaged
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

See [architecture](ARCHITECTURE.md), [migration notes](docs/MIGRATION.md), and
[verification](docs/VERIFICATION.md) for implementation and validation details.
