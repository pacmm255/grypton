# Verification

**Scope correction after comparing the original source:** the results below
validate the separate supplied-evidence review application and its restored
target-first console contracts. They do not validate Krypton's continuous hunt
sessions, workspace compatibility, or finding accuracy. No comparative accuracy evaluation was run.
The original project's tests were archived, not ported or executed as Grypton
acceptance tests. See [the compatibility audit](KRYPTON_PARITY_AUDIT.md).

Verified locally on 2026-09-09. No original target data was used and no target
interaction was performed. Provider requests contained synthetic material only.

## Runtime integration

- Installed OpenCode version: 1.18.30.
- Installed Codex version: 0.153.4.
- `doctor` passed binary, authentication, model variant, and Codex flag checks.
- Each adapter returned valid JSON for an independent synthetic connection check.
- The new standalone role consoles completed fresh synthetic calls through
  `zai-coding-plan/glm-5.3` at `max` and
  `opencode-go/muse-spark-1.3-contributor` at `xhigh`.
- A fresh, one-call Astra check returned a schema-valid supported/unknown verdict
  for a synthetic configuration observation and cited only its supplied evidence ID.
- One complete synthetic remediation review passed manager planning, worker
  assessment, a bounded local follow-up, independent Codex validation, and
  manager summary.
- The live review used `zai-coding-plan/glm-5.3` at `max`,
  `opencode-go/muse-spark-1.3-contributor` at `xhigh`, and Codex
  `gpt-6-astra` at `max`.
- A fresh live no-evidence kickoff used Muse/Kryptex to remember the directive,
  resolve local scratch support, and delegate immediately to GLM/Kraude. See
  [live-kickoff.json](verification/live-kickoff.json). Neither Spark's raw reply
  nor the final operator-facing response matched the passive-refusal detector.
- A fresh live finding validation used Muse → Astra → Muse. Astra received only
  `claim` and `evidence`; all three calls completed at the exact configured
  effort. See [live-finding-validation.json](verification/live-finding-validation.json).
- The validator supported only the supplied configuration-change claim, with
  severity `unknown`. No runtime impact or live reproduction was asserted.

The initial full integration run exercised five calls, including one follow-up.
Afterward, redundant requests for already supplied evidence were eliminated and
covered by an offline regression test. The final router still permits at most
one follow-up when a new local resource is actually supplied. No model route or
effort setting was changed.

See the machine-readable [live check](verification/live-check.json) and the
[synthetic report](verification/synthetic-live-review.md). These record an
observation at the time of checking, not a guarantee of future quota or service
availability.

## Regression tests

Run `python3 -m unittest discover -s tests -v`. All 56 tests passed, covering:

- Isolated provider configuration, exact model routes, and disabled execution.
- Credential redaction, error events, bounded output, and process-tree cleanup.
- Snapshot integrity, duplicate evidence, restrictive permissions, concurrent
  state updates, path exclusions, and visible corruption errors.
- Independent validator inputs and rejection of fabricated evidence references
  or unsupported severity claims.
- Complete reviews, no-evidence failure, checkpoint reuse, changed-evidence
  rejection, stale verdicts, concurrent review exclusion, and cancellation.
- Bounded local requirement handling and duplicate-resource suppression.
- JSON CLI output, errors, dry runs, and every packaged offline scenario.
- Target-first initialization without `--claim`, target/title resolution,
  both positional and `--target` forms, automatic scope seeding, persistent
  operator directives, no-evidence Kryptex-to-Kraude kickoff, and automatic
  return of sequential local blockers to the requesting role.
- Versioned scope, observations, surface records, persistent finding ledger,
  prompt provenance, per-call audit digests, finding-validation cancellation,
  and direct lab run/score round trips.
- Dashboard asset/API responses, host/origin checks, rejected write requests,
  conversation redaction, integrity API, and rejection of arbitrary file paths.

## Terminal checks

A pseudo-TTY walkthrough passed `init --target <target> --mock`, automatic scope
seeding, `/status`, `/scope`, `/note`, `/surface add`, a natural `pentest`
directive, automatic relay to Kraude, `/evidence`, `/finding add`, `/validate`,
`/findings`, `/history`, `/review`, `/resources`, and `/stop`. It checked durable
records, the independent mock verdict, model-call audit records, and the empty
target directory. Source and wheel-installed role entry points also passed.
See [console-check.json](verification/console-check.json).

## Browser checks

`python3 tests/ui_smoke.py` passed with Playwright and local Chrome at widths
1440, 768, and 390 pixels. It checks selection, search, status filtering, refresh,
literal rendering of markup in case titles, zero horizontal overflow, and zero
browser errors. It also checks the system-integrity panel and nine-turn lab. It
uses temporary synthetic records and removes them afterward.

See [browser-check.json](verification/browser-check.json),
[desktop screenshot](verification/dashboard-desktop.png), and
[mobile screenshot](verification/dashboard-mobile.png).

## Fork integrity

`grypton audit --auth` passed all 17 active checks: exact model routes,
independent Codex isolation, three prompt fingerprints, eight skills, the fixed
lab, dashboard assets, package version, three launchers, empty `target/`, absent
`targets/`, 28 preserved hashes, all 39 recorded original-source hashes, both
connector credentials, the supplied Go-key match, and credential exclusion from
source/docs/tests/snapshot. It made zero model calls and opened no target,
session, or runtime data. See [request audit](verification/request-audit.json).

The complete mock lab ran all three scenarios and nine evidence transitions,
then rescored its saved output. Validator payload keys were exactly `claim` and
`evidence`; tool, network, and target-interaction counts were zero. See
[lab-check.json](verification/lab-check.json). Its mock score is a harness result,
not a finding-accuracy measurement.

The package builds as a wheel with prompts, skills, scenarios, and dashboard
assets contained in the distribution. Its installed package excludes the
archived `upstream/` application.

The 2.1.0 wheel built successfully. A clean isolated installation passed the
main CLI plus the `kraude` and `kryptex` entry points. The existing Python 3.13
`.venv` was refreshed in editable mode with `uv`. See
[package-check.json](verification/package-check.json).
