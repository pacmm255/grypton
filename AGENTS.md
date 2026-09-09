# Working on Grypton

- Work only in this fork. Do not inspect or copy `/root/krypton/targets`, any
  other `targets` directory, or legacy target/session/runtime data.
- `upstream/` is a preserved source snapshot, excluded from the installed package.
  Keep its files unchanged so `FORK_MANIFEST.json` remains verifiable.
- The active application reviews supplied evidence and remediation. Keep model
  adapters text-only and preserve the independent validator boundary.
- Keep exact requested model/provider/effort routes explicit. Never silently
  switch providers, plans, reasoning settings, or models.
- Never print credentials or commit runtime state. `target/` should remain empty
  unless the operator later explicitly populates it.
- Run `python3 -m unittest discover -s tests -v` after substantive code changes.
  The optional `tests/ui_smoke.py` checks the dashboard with synthetic data.
  Do not run the archived tests in `upstream/tests/`.
