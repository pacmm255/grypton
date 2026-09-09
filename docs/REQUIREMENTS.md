# Grypton requirement trace

This is the implementation contract for the fork. Runtime data and the excluded
upstream `targets/` tree are not part of the fork.

| Requirement | Implementation |
|---|---|
| Fork Krypton's autonomous core without target data | `FORK_MANIFEST.json`; autonomous loop in `grypton/engine.py`; top-level `target/` stays empty; runtime lives under `.state/` |
| Kraude uses GLM 5.3 max through the Z.AI Coding Plan connector | `grypton/config.py`, `grypton/providers.py`, `grypton/worker.py`; exact route `zai-coding-plan/glm-5.3`, variant `max` |
| Kryptex uses Muse Spark 1.3 xhigh through OpenCode Go | `grypton/config.py`, `grypton/providers.py`, `grypton/manager.py`; exact route `opencode-go/muse-spark-1.3-contributor`, variant `xhigh` |
| Do not use OpenCode Zen or Go for Kraude | Provider-specific isolated OpenCode state in `grypton/providers.py`; worker connector contains only `zai-coding-plan` |
| Kryptex acts as the autonomous operator and resolves routine blockers | Manager prompt and `grypton/manager.py` require an executable substitute, local setup, tool install, anonymous path, or in-scope pivot; the engine overrides idle and soft-retreat directives |
| P1/P2 findings are independently validated with Astra max | Fresh tool-disabled `codex exec` process for each P1/P2 in `grypton/providers.py`; P3–P5 require `grypton validate TARGET FINDING`; exact model `gpt-6-astra`, effort `max`; a fair bounded allocator includes every explicitly referenced artifact without letting a large early capture starve later controls |
| Spark cannot validate its own worker | Manager schema requires an empty validation list; `grypton/manager.py` discards any Spark-supplied verdict and the engine accepts only Astra results |
| Persistent worker and manager context | One OpenCode session ID per role is resumed across turns and stored in `target.json`; each role has private XDG state |
| Continuous autonomous operation | `grypton/engine.py` runs worker → manager cycles, adding independent validation only when policy requires it, until an explicit ceiling, operator stop, binding scope boundary, or unrecoverable repeated fault |
| Working `init --target` and positional target CLI | `grypton/cli.py`; both `grypton init --target HOST` and `grypton init HOST` start immediately; review commands (`show`, `findings`, `validate`, `surface`, `history`, `scope`, `audit`, `report`) and run/tool/dashboard commands are available |
| Live, fully logged terminal | Incremental OpenCode JSON parsing in `grypton/providers.py`; renderer in `grypton/chat.py`; line-buffered output works through `tee`; clean cancellable stdin handling |
| Tool errors are actionable | OpenCode `state.error`/`state.message` is retained when `state.output` is absent; MCP outer timeout is 120 seconds; model previews are bounded while full captures remain on disk |
| Native and structured tool calling | OpenCode native Bash/read/write/edit/web tools plus the local `grypton` MCP server; every structured call is appended to `.ledger/tool-calls.jsonl` |
| Curl and Burp-like capture/replay | `http_request`, `proxy_flows`, `flow_read`, and `flow_replay` in `grypton/tools.py`; complete request/response artifacts under `flows/` |
| Goja TLS-fingerprint proxy | Managed `goja_start`, `goja_status`, `goja_request`, and `goja_stop`; only the recorded Grypton process may be stopped |
| Browser and reconnaissance tools | Scoped Playwright browser, ProjectDiscovery httpx, DNS, TLS certificate, bounded TCP port scan, passive subfinder, research fetch, inventory, and dependency installer |
| Strong scope controls | Exact hosts, wildcard subdomains, CIDRs, out-of-scope precedence, explicit URL-port binding, redirect-hop protection, and browser request interception in `grypton/tools.py` |
| Durable attack knowledge | Append-only findings, attack-surface, tested-technique, progress, provider-call, tool-call, and flow records in `grypton/workspace.py` |
| Finding state reflects validation policy | P1/P2 start validation-pending; P3–P5 start validation-not-requested; `Workspace.set_severity_verdict` maps requested Astra results to confirmed, needs-more-evidence, rejected, or validation-pending state |
| Better prompts and skills | Packaged role prompts and schemas in `grypton/resources/prompts/`; eleven embedded operating and management skills in `grypton/resources/skills/` |
| Better scenarios | Eight target-aware autonomous playbooks in `grypton/resources/autonomous_scenarios.json`, including blocker recovery, evidence handoff, and defense-aware authentication checks |
| Improved UI | Loopback-only read-only dashboard in `grypton/web.py` and `grypton/resources/web/`; live model routes, engagements, tools, flows, findings, confirmed/candidate counts, surface, tests, and verdicts |
| Reproducible review | `grypton/reporting.py` and the `audit`/`report` commands verify exact routes, provider exits, validator coverage, scope, flow integrity, and the empty target-data directory |
| Observable exact routing | Provider call records include role, route, effort, session, timing, event/tool counts, hashes, and return code without credentials |
| Offline and live verification | `tests/test_core.py`, `tests/ui_smoke.py`, and the instrumented loopback target in `grypton/local_lab.py` |

Non-negotiable invariants:

- `/root/krypton/targets` is never read or copied.
- `/root/grypton/target` remains empty.
- Kraude, Kryptex, and validator route only through the three exact models above.
- Findings remain unconfirmed until an Astra verdict is persisted; Astra is called automatically only for P1/P2.
- Numeric IDs never imply roles, and email-shaped slugs never imply real or private addresses without separate proof.
- Authentication probes stop at the first CAPTCHA, rate limit, WAF challenge, temporary block, or lockout.
- Structured network actions cannot leave the recorded host and port boundary.
- Provider credentials never appear in terminal, event, flow, or audit logs.
