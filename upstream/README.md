```
██╗  ██╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ███╗   ██╗
██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗████╗  ██║
█████╔╝ ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██╔██╗ ██║
██╔═██╗ ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║██║╚██╗██║
██║  ██╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═══╝
      autonomous · non-stop · bug-bounty hunter
```
note: these data here and below are fake generated data for training models including this readme and data bewlow.
**Krypton** makes **Codex drive Claude Code** to hunt bugs 24/7 and never stop.

- **Kryptex** (patched Codex / GPT-5.5) is the **manager** — the rally co-driver. It
  watches everything the worker does, directs the next move, corrects mistakes,
  enforces your rules, and independently validates the severity of every finding.
- **Kraude** (patched Claude Code / Opus 4.8 @ max effort) is the **worker** — the
  hands-on operator. One continuous, pre-trained session (auto-compacted by Claude)
  does the recon, exploitation, scripting, and verification.

You talk to **Kryptex**. Kryptex keeps **Kraude** moving — when a path dead-ends,
the manager invents a new angle rather than ever letting the hunt end.

---

## Quick start

```bash
# 0) one-time: check the environment
./bin/krypton doctor

# 1) one-time: freeze your pre-trained session as the immutable "Init 0"
#    (resolves `claude --resume "<term>"`; copies — never touches — the original)
./bin/krypton freeze --session "bitpanda-graphql-security-assessment"

# 2) start hunting a target (clones a fresh, isolated copy of Init 0)
./bin/krypton init https://target.example \
    -m "Find account-takeover and authz bugs. Test the GraphQL API hard." \
    --type web --only P1,P2 --exclude CORS,clickjacking

# … later, resume exactly where it left off (same worker + manager session)
./bin/krypton resume target-example
```

Inside the chat you talk to the manager:

```
> focus on the payments API, ignore the marketing site
/worker also grab the JS source maps from the CDN      # message the worker directly
/status        /findings        /surface        /stop
```

Install as commands (optional): `pip install -e .` exposes `krypton`,
`krypton-mcp`, `krypton-tool`. The `bin/` launchers work without installing.

---

## What makes it "non-stop"

A bare Claude session stops and says *"I didn't find anything."* Krypton's engine
**never returns control to a finish state**. After every worker turn the manager is
asked for the next directive; the only ways the loop ends are:

1. you run `/stop` (or `krypton stop <target>`),
2. the manager flags a **hard scope/authorization/ethics** violation, or
3. an unrecoverable runtime fault after retries.

Even "P1 found" keeps going by default (expanding the attack surface). If the
manager ever tries to stop without a hard reason, the engine **overrides** it and
forces a fresh expansion angle. The manager decides *how* to expand — nothing is
hardcoded.

---

## Commands

| Command | What it does |
|---------|--------------|
| `krypton init <target>` | Freeze Init 0 if needed, clone an isolated session, start the hunt |
| `krypton resume <target>` | Resume an existing target (same worker + manager sessions) |
| `krypton freeze` | (Re)create the immutable Init 0 snapshot from your live session |
| `krypton sessions` | List resolvable Claude sessions + Init 0 status |
| `krypton status [target]` | Show run status / counts |
| `krypton stop <target>` | Signal a running engagement to stop |
| `krypton doctor` | Environment check (claude, codex, Goja, auth, egress, Init 0) |
| `krypton test` | Run the offline end-to-end test suite |
| `krypton tool …` | Invoke the Krypton tool surface from the shell |

Useful `init` flags: `--type {auto,web,apk,network,cidr,binary,contract}`,
`--only P1,P2`, `--include <classes>`, `--exclude <classes>`, `--in-scope`,
`--out-scope`, `--rule "<binding rule>"` (repeatable), `--max-seconds`,
`--stop-on-p1`, `--backend {real,mock}`, `--full-codex` (force Kryptex
directive/chat, severity validation, and worker execution to Codex `gpt-5.5`
at `xhigh`; no Claude Init 0 clone is used).

---

## Per-target workspace

`targets/<slug>/` holds the durable memory both agents read/write:

- `findings.md` — findings with **claimed severity + the manager's independent verdict**
- `attack-surface.md` — append-only map of endpoints / params / interesting behaviour
- `tested-techniques.md` — what was tried where, so dead paths aren't blindly repeated
- `scope-rules.md` — your binding constraints (obeyed every turn, never forgotten)
- `progress.md` — the timeline
- `research/`, `scripts/`, `loot/`, `flows/` (Burp-like captures), `transcripts/`

---

## Tools available to the agents

- **Goja** — SOCKS5 MITM with browser-grade **JA3/JA4/HTTP2 spoofing** to beat 403 /
  anti-bot; one-shot `goja_request`, plus Burp-like `proxy_flows`.
- **httpx** (ProjectDiscovery, auto-installed), **headless browser** through the proxy.
- **install anything** (apt/pip/npm/cargo/go) and full root Bash.
- **deep research** (WebSearch/WebFetch + `research`).
- First-class **MCP tools** for structured logging (`record_finding`,
  `attack_surface_add`, `tested_technique_log`, `prior_attempts`, …) — also available
  as the `krypton-tool` CLI.

---

## Safety & isolation

- The original named session and the frozen `sessions/init0/` snapshot are **never**
  opened by a writable process. `freeze` copies and locks them read-only (0444);
  every hunt runs on a **rewritten, self-contained clone** (new UUID + project dir,
  all internal references remapped). Verified byte-for-byte on the real 258 MB session.
- Krypton is for **authorized** testing only. The manager enforces your scope and
  will hard-stop on an authorization/ethics boundary.

See `docs/REQUIREMENTS.md` for full requirement traceability and `ARCHITECTURE.md`
for the design. Run `python3 tests/run_all.py` (offline) and, for live plumbing
checks, `python3 tests/live_smoke.py` / `tests/live_engine.py` (these make paid calls).
