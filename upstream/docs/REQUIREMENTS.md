# Krypton — Requirements Traceability

Every requirement from the founding brief, mapped to where it is implemented.
This file is the contract; nothing here may be silently dropped.

| # | Requirement (verbatim intent) | Implemented in |
|---|-------------------------------|----------------|
| R1 | Continuous, non-stop 24/7 bug-bounty hunting | `engine.py` (NeverStop loop) + `prompts/manager_system.md` |
| R2 | Codex = manager, Claude Code = worker | `manager.py` (kryptex) + `worker.py` (kraude) |
| R3 | Codex drives ONE Claude session (not new sessions); auto-compaction handles fill | `worker.py` keeps a single resumed stream-json session for the whole run |
| R4 | Worker uses Opus 4.8 at max effort | `config.WORKER_MODEL=claude-opus-4-8`, `WORKER_EFFORT=max` |
| R5 | First run clones the user's live `bitpanda-graphql-security-assessment` session = "Init 0" | `sessions.resolve_named_session` + `sessions.freeze_init0` |
| R6 | Freeze Init 0; never touch the original session or its files/history | `sessions.freeze_init0` (read-only copy + chmod 0444 + manifest), `sessions.IsolationGuard` |
| R7 | Each first run clones a fresh copy of Init 0; isolation guaranteed | `sessions.clone_for_target` (UUID + path rewrite, new project dir) |
| R8 | Krypton options: `init` and `resume` | `cli.py` subcommands `init`, `resume` |
| R9 | Fully CLI based; forked/patched codex+claude framework (kryptex + kraude) | `bin/kraude`, `bin/kryptex`, `bin/krypton`; wrappers patch behavior, prompts, flags |
| R10 | User talks to Codex; Codex messages Claude (user may also message Claude directly) | `chat.py` (default route → manager; `/worker` routes → worker) |
| R11 | Manager watches Claude and directs it like a rally co-driver; no "I found nothing & stop" | `engine.py` digest→directive cycle + manager system prompt |
| R12 | On true exhaustion, never finish: invent new methods, expand attack surface, more recon/thinking — AI-decided, not hardcoded | `engine.ExhaustionPolicy` + manager prompt "expansion doctrine" (no hardcoded techniques) |
| R13 | Chat like claude/codex CLI (forked/patched one of them) | `chat.py` REPL with live worker stream + manager turns |
| R14 | Patches: live non-stop process, full integration, tool-calling, mutual consult | `engine.py`, `toolserver.py`, `manager.py` consult bridge |
| R15 | Kryptex & Kraude consult each other, exchange ideas, correct mistakes | `engine.py` (cross-talk + `ask_manager`/`ask_worker` tools), anti-fabrication confront |
| R16 | Many tools for flexibility | `tools.py` + `toolserver.py` (MCP) |
| R17 | Goja (`/root/Goja`) for JA3/JA4 fingerprint spoofing / 403 & anti-bot bypass | `tools.GojaProxy` + MCP `goja_request` / `goja_proxy_start` |
| R18 | MITM proxy + browser so Krypton "sees requests" like Burp | `tools.GojaProxy` (SOCKS5 MITM) + `tools.Browser` + flow capture; MCP `proxy_flows`/`browse` |
| R19 | httpx (ProjectDiscovery) available | `tools.Httpx` (auto-install) + MCP `httpx_probe` |
| R20 | Ability to install ANY tool/dependency on the OS | `tools.Installer` + MCP `install_tool`; worker runs with bypassPermissions + full bash |
| R21 | Per-target directory with multiple .md files | `workspace.py` (`Workspace` creates target dir + canonical docs) |
| R22 | findings.md | `workspace.Workspace.findings_path` |
| R23 | attack-surface.md, appended as surface/points/interesting things are found | `workspace.append_attack_surface` + MCP `attack_surface_add` |
| R24 | tested-techniques file per endpoint/path/surface (avoid repeating blocked paths; not bypass-trials) | `workspace.log_tested_technique` + MCP `tested_technique_log`; dedupe via ledger |
| R25 | Write & run custom scripts | worker native Bash/Write + workspace `scripts/` dir |
| R26 | Think creatively; connect paths/points/clues; be smart | manager+worker system prompts ("synthesis doctrine") |
| R27 | Obey user instructions exactly & never forget (e.g., only P1/P2; never test CORS) | `workspace.Constraints` (scope-rules.json/md) injected every turn into BOTH agents; manager enforces |
| R28 | Codex independently validates severity of Claude's findings, with full detail access | `manager.validate_severity` + `prompts/severity_schema.json`; recorded in findings.md |
| R29 | Both agents self-aware of role/state | system prompts + per-turn self-awareness header |
| R30 | Manager has vision/access to all Claude did; can correct/use/extend | `engine.digest` feeds full worker activity + workspace docs to manager |
| R31 | Edit system prompts for both | `prompts/worker_system.md`, `prompts/manager_system.md` (+ injected via flags) |
| R32 | Deep internet research for any tech/issue/idea | `tools.Research` (WebSearch/WebFetch via worker; MCP `research`) |
| R33 | Stable, clean, handled, smart, game-changing; no missing points | this table + `engine` error handling + tests |
| R34 | End-to-end tests on all scenarios/flows/possibilities | `tests/` (offline mock E2E + live smoke) |

## Non-negotiable invariants
- **I1**: A writable `claude` process is NEVER pointed at the original named session. Only `freeze` reads it (copy), once.
- **I2**: The frozen `sessions/init0/` snapshot is immutable (0444) and checksummed; clones derive from it, never from the live session.
- **I3**: The loop never self-terminates. The only stops are: explicit user `stop`, a hard scope/authorization violation, or an unrecoverable runtime fault — each logged with a reason.
- **I4**: User constraints (scope-rules) are re-asserted to both agents every single turn and enforced by the manager before any finding is surfaced.
