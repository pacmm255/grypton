# Verification

Verified locally on 2026-09-09. No original target data was used and no target
interaction was performed. Provider requests contained synthetic material only.

## Runtime integration

- Installed OpenCode version: 1.18.30.
- Installed Codex version: 0.153.4.
- `doctor` passed binary, authentication, model variant, and Codex flag checks.
- Each adapter returned valid JSON for an independent synthetic connection check.
- One complete synthetic remediation review passed manager planning, worker
  assessment, a bounded local follow-up, independent Codex validation, and
  manager summary.
- The live review used `zai-coding-plan/glm-5.3` at `max`,
  `opencode-go/muse-spark-1.3-contributor` at `xhigh`, and Codex
  `gpt-6-astra` at `max`.
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

Run `python3 -m unittest discover -s tests -v`. All 34 tests passed, covering:

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
- Dashboard asset/API responses, host/origin checks, rejected write requests,
  and rejection of arbitrary file paths.

## Browser checks

`python3 tests/ui_smoke.py` passed with Playwright and local Chrome at widths
1440, 768, and 390 pixels. It checks selection, search, status filtering, refresh,
literal rendering of markup in case titles, zero horizontal overflow, and zero
browser errors. It uses temporary synthetic records and removes them afterward.

See [browser-check.json](verification/browser-check.json),
[desktop screenshot](verification/dashboard-desktop.png), and
[mobile screenshot](verification/dashboard-mobile.png).

## Fork integrity

All 28 preserved source files match `FORK_MANIFEST.json`. `/root/grypton/target`
remains empty. Exact-value checks found no supplied OpenCode keys in the new
source, preserved source, tests, or documentation. No global CLI configuration
or original project files were modified.

The package builds as a wheel with prompts, skills, scenarios, and dashboard
assets contained in the distribution. Its installed package excludes the
archived `upstream/` application.

The final wheel built with zero warnings. An isolated installation under Python
3.13.13 passed a CLI mock review, Markdown report, and resource-load checks from
outside the source directory. See [package-check.json](verification/package-check.json).
The local `.venv` was then installed in editable mode for continued development.
