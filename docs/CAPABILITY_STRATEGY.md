# Grypton capability strategy: accuracy, creativity, and coverage

Date: 2026-10-25 · Status: proposal for operator review · Method: code-anchored gap
analysis plus four external model consultations (Astra `gpt-6-astra`, Claude Opus
5.5, Claude Fable 5.1, OpenAI Daybreak), synthesized against the live codebase.

Goal restated from the operator: find the most complex, multi-step bugs; reproduce
them without hallucination; rate severity correctly; keep opening new attack
surface instead of cycling known techniques; know common technologies and be able
to research them online; test access-control decisions behind 403/WAF responses
within program rules; and see browser traffic the way a web pentester sees it in
Burp Suite.

---

## 1. Verified current-state gaps (the levers)

Every row was verified in code during the 2026-10-25 deep pass:

| # | Gap | Evidence | Consequence |
|---|-----|----------|-------------|
| G-1 | Worker static prompt is one line of scope data; the 11 methodology skill files and every playbook's `moves` are dead code (`scenarios.guidance()` never called) | `resources/prompts/worker_system.md` = `%%CONSTRAINTS%%`; `resources/skills/*.md` unreferenced; `tests/test_core.py:2290-2308` asserts no embedded skills | Kraude hunts on model memory alone; the repo's best methodology prose never reaches any model |
| G-2 | `research` = 18 fixed documentation hosts, GET only, query strings banned | `tools.py:11558-11565` `_RESEARCH_DOCUMENTATION_HOSTS`, `tools.py:12083` | No search engines, GitHub, CVE/NVD/GHSA, or writeups — fingerprint-driven research impossible |
| G-3 | Defense signals handled only on the credential path; general 403/429/WAF pages get no classification, no ledger flag | auth-only: `tools.py:927-940`, `credentials.py:1836-1845`; nothing in the `http_request` result path | Worker can hammer a WAF unknowingly, or abandon surface on a plain 403 that was real access-control information |
| G-4 | No content discovery, no GraphQL introspection, no source-map parsing, no JWT decode, no OOB callback (blind SSRF), no race runner; WebSockets force-closed; `apk_extract_asset` is `assets/`-only | `tools.py:3702-3705` (WS close), allowlists `tools.py:11552-11556` | Whole vulnerability classes structurally unreachable |
| G-5 | Browser capture is not Burp-parity: final DOM + main request only; XHR/fetch subresources not captured as full request/response pairs; no intercept/replay; no storage inspection | `browse`/`browser_workflow` capture paths; CDP capture exists only in the auth path (`tools.py:4720+`) | SPA/postMessage/CORS classes cannot be evidenced properly |
| G-6 | Severity at record time is raw worker judgment; P3–P5 never validated | `toolserver.py` record_finding schema (bare `P1..P5`); `config.py:186-191` | Systematic over/under-claiming; under-claiming silently shrinks reports |
| G-7 | `record_finding` gate checks nonempty narrative fields — not that referenced evidence exists, contains a control, or supports the claim | `toolserver.py:49` `_record_finding` | Fabricated or one-off observations can reach Astra (Astra catches some, at cost) |
| G-8 | Evidence snapshots hash artifacts but scrape paths heuristically from prose and lose endpoint/principal/control relationships; validator schema mixes validity with severity adjustment and asks a tools-denied reviewer about "reproducing" | `manager.py:694-807`, `severity_schema.json:9,20-25` | Reviewer anchoring and ambiguity; verdict semantics conflated |
| G-9 | Stagnation response is a counter-driven carousel of 14 one-sentence playbooks with no memory of why a rotation failed; deadline mode pivots forever | `engine.py:2028-2045`, `scenarios.py:83-97`, `engine.py:854-862` | Hours of churn re-testing known things; rotation ≈ repetition |

---

## 2. Strategy: eight workstreams

Three consultants independently converged on the same core: **make Grypton an
evidence-quality system first, then expand probing** — mechanical evidence gates,
public-standard severity, evidence-driven (not index-driven) exploration.

### WS1 — Evidence integrity and anti-hallucination (highest priority)

Converged design (Opus + Astra + Fable), implemented in three layers:

**Layer 1 — structured evidence packages at `record_finding`.** Replace free-text
`evidence` as the validation basis with an explicit package (required for
auto-validated severities):

```json
"evidence_package": {
  "positive_flow_id": "flow-0042",
  "control_flow_id": "flow-0043",
  "replay_flow_id": "flow-0051",
  "second_run_flow_id": "flow-0052",
  "differential_claim": {
    "dimension": "status|body_sha256|header_present|header_value|timing|body_bytes",
    "predicate": "differs|equals|positive_matches",
    "positive_value": "...", "control_value": "..."
  },
  "changed_variable": "the single variable that differs",
  "precondition_notes": "auth state, roles, owned-vs-other object IDs",
  "environment_notes": "origin/edge node, cache state, time window, identity header"
}
```

Astra's corrections to the naive model: a **control must test a specific
alternative explanation** (not merely produce a different response); replays must
not reuse contaminated state; races need numerator/denominator trial records, not
"two successes"; irreversible actions accept a surrogate or staging reproduction
instead of a harmful repeat.

**Layer 2 — mechanical verifier before the ledger accepts the finding**
(`verify_evidence_package(ws, pkg)` inside `Workspace.record_finding`, reusing
`_flow_path` path-safety and the `_evidence_snapshot` digest logic):
1. every referenced flow exists and resolves inside `flows/`;
2. hash-chain: store per-flow digests + `evidence_chain_sha256`; pin the chain in
   the verdict so it cannot survive a silent evidence swap;
3. replay integrity: replay flows' `transport` metadata must be
   `replay:<positive-stem>` (proves machine replay, not hand-authoring);
4. request identity: method + request-target digest equal across
   positive/replay/second-run; control differs only in the declared variable;
5. **digest supports the claim**: evaluate the `differential_claim` predicate
   against computed digests (this is the step that makes fabrication fail at
   write time); deterministic classes require body-sha equality across replays;
   race/cache classes require the declared predicate across enumerated runs;
6. freshness: replays captured after the positive.

Missing control ⇒ return "insufficient — remains a hypothesis" and route to the
surface/precursor ledgers instead. Extend `antifab` so every quantitative claim
in `description`/`poc` (status code, byte count, returned value) must appear
verbatim in a referenced flow.

**Layer 3 — admission states and provenance (phased).** Astra's fuller model:
`hypothesis → evidence-incomplete → review-ready → reviewed`; only review-ready
enters Astra's queue; failures return to evidence-incomplete, not "false
vulnerability". Longer-term: collector-owned receipts binding capture digest +
tool invocation ID + policy decision, so worker-writable files can never
self-certify. Phase 1 ships Layers 1–2 (engine-computed digests already give
collector-side trust); full receipts are Phase 3.

Class-specific reproduction minimums (Astra): deterministic read-only → two
independent positive/control pairs; stateful → before/after state + independent
readback; client-side → real browser context + separate affected principal +
proof the observation wasn't console/DOM-created; probabilistic → full trial
ledger.

**Metrics:** fabricated-finding acceptance rate = 0 at the verifier (seed
fabrications in tests: no control, swapped digest, hand-authored replay, DOM-only
claim, single lucky run); artifact-completeness rate; local-verifier vs Astra
digest agreement = 100%.

### WS2 — Severity calibration (VRT + CVSS 4.0 dual-coding)

Separate three decisions (Astra): **validity** (confirmed/needs-more/rejected),
**technical severity**, and **program eligibility**. Store on every case:
`vrt_node` + `vrt_version` (pin an exact release; vendor the VRT JSON and
validate at write time), `cvss_vector`/`cvss_score`/`cvss_severity` (v4.0),
derived `severity` (P1–P5 kept for back-compat), `severity_basis`
(`vrt_default|cvss_override|program_adjustment`).

Rules (Opus + Astra merged):
- precedence: program-specific matrix → pinned VRT node → documented internal
  fallback; never convert CVSS bands directly to P-levels;
- the worker picks the **most specific VRT node the evidence supports**; severity
  follows the **worst demonstrated operation**, never the worst imaginable;
- no arithmetic penalties ("authenticated = −1") — prerequisites are usually
  already inside the VRT node; double-counting is the classic error;
- tie-break: VRT-default vs CVSS-band disagree by one level → take the lower
  unless the package contains a confirmed cross-account/cross-privilege
  differential;
- **anchoring mitigation**: Astra's first classification pass does not see the
  worker's proposed severity.

Boundary rulings (merged from all three, as seed content for
`resources/severity_rubric.json`): self-XSS P5 absent an evidenced cross-user
boundary; reflected XSS typically P3 by context (traffic alone neither raises nor
lowers); stored XSS into a privileged victim's context P2 (requires cross-account
control in the package); blind internal-only SSRF P3, response-bearing internal
P2, cloud-metadata-with-retrieved-credentials P1–P2; IDOR read non-sensitive
P4 / PII P2–P3 / write rated by the action's security effect; rate-limit weakness
informational alone — rate the separately evidenced abuse; secret vs metadata
exposure rated by what the secret unlocks, "proven live" required to exceed P4.

Validator schema replacement (`severity_schema.json`): drop the mixed
verdict/severity semantics and the "did you reproduce" wording (it conflicts with
the tools-denied boundary). New output: `validity`, `assigned_severity|null`,
`severity_rule_id`, `supported_claim_ids[]`, `unsupported_claim_ids[]`,
`contradictions[]`, `missing_evidence[{claim_id, required_observation, reason}]`,
`evidence_limitations[]`, `evidence_chain_ack`, `artifact_checklist[]`,
`confidence` (high only when all four roles corroborate). Upgrade/downgrade is
computed by comparing assigned vs proposed — not asked.

Astra's fast review layout: claim + invariant first, then principal/object
relation table, positive/control comparison, replay/repetition summary, decisive
excerpts (trusted extraction around the claimed predicate, replacing arbitrary
head/tail), contradictions, applicable rule.

**Metrics:** three-way agreement (worker vs validator vs final program triage):
within-one-level ≥ 0.9, exact VRT-node ≥ 0.8; weighted κ ≥ 0.8 on an adjudicated
corpus; investigate every two-level disagreement as a rubric or evidence gap.

### WS3 — Chain discovery: precursor ledger + staged chain playbooks

Fable's highest-value recommendation: chains are found when two clues meet in
working memory; make that structural.

- New ledger `.ledger/precursors.jsonl` + tool `precursor_note`: rows record an
  observed signal (`signal_class`, flow ID, confidence ≤ 1.0), the chains it
  enables, and a **required `refuting_observation`** (what would disprove it).
- Engine post-turn pass (where deltas are already computed) scans tool results
  against a fixed **signal dictionary** and auto-appends precursors; open
  precursors feed Kryptex's next-direction context.
- Playbooks gain `activation_signals` and staged structure:
  `stages: [{goal, precursor/gate, differential, false_positives}]`. Seed six
  staged chain playbooks from Fable's per-class content: SSRF→metadata→
  credentials; cache poisoning/deception (unkeyed input + cacheable response ⇒
  mark/clean-view/negative-control triple); race/TOCTOU (serial baseline then
  bounded burst, durable-state differential); OAuth/SSO binding confusion
  (map enforced bindings on a valid baseline, vary one at a time); cross-origin
  postMessage/CORS (credentialed cross-origin read vs disallowed-origin
  control); business-logic state-machine abuse (skip/reorder/repeat/downgrade/
  stale-resume transitions with invariant before/after).
- `directive_schema.json` gains a required `chain_hypotheses:
  [{precursor_id, target_chain, next_differential}]` so Kryptex must connect an
  open precursor to a staged chain each turn — replacing index-driven rotation
  with evidence-driven escalation.
- Astra's chain rules: `chain_id` is separate from the root-cause family (a chain
  may cross several root causes); each link needs starting principal/state, input
  capability from a preceding observation, output capability, and evidence
  connecting output→next link; rate the **supported terminal outcome**; partial
  chains stay explicitly partial; do not require individual links to be harmless.

### WS4 — Technology knowledge packs

Schema (`resources/knowledge/*.json`, loaded like scenarios): `fingerprints[]`
(signal, source header/body/JS, confidence), `version_signals[]` (regex),
`checks[]` — each `{observable → implication → probe → differential →
false_positives → severity_hint}` — plus `error_signatures[]`,
`header_semantics[]`, `cache_key_notes`, `sources[]`, review date. Packs are
checklists keyed to observables already visible in captured flows, not prose.

Priority classes (Fable): reverse proxies (nginx, Apache, Traefik, Envoy,
HAProxy, IIS); CDNs/edge (Cloudflare, Fastly, Akamai, CloudFront — cache-key
behavior, edge-vs-origin signatures); frameworks (Next.js, Django, Rails, Spring,
Laravel, Express — debug/actuator endpoints, error signatures, mass-assignment
shapes); auth stacks (Keycloak, Auth0, Okta, Firebase, generic OIDC); cloud API
recognition semantics; GraphQL stacks (Apollo, Hasura); k8s ingress/mesh;
admin/message consoles.

Astra's pack additions: expected security invariants per class,
owner-controlled verification fixtures where applicable, expiry/review dates, and
taxonomy mappings. Fingerprints are hints, never proof of version or flaw.

Injection point: **match packs against attack-surface fingerprints in the engine
post-turn pass and inject only matched `checks` into Kryptex's per-turn context**
— not Kraude's static prompt — so `WORKER_PROMPT_CONTRACT_VERSION` stays stable
and live sessions are not retired (Fable). This same path finally wires the
currently-dead skills content (hypothesis-testing, finding-quality,
flow-analysis) into the loop, resolving gap G-1 within the minimal-prompt
doctrine (see D1).

Provenance: `grypton audit` verifies packs parse and that any pack cited by a
finding existed at run time — "the model remembered a CVE" is not an evidence
source.

### WS5 — Research capability: two-tier, egress-firewalled

Keep the 18-host docs allowlist as Tier 0. Add **Tier 1 structured intelligence**
(`_RESEARCH_INTEL_HOSTS`, separate code path): NVD REST, GitHub GHSA/advisories
API, vendor advisory domains — typed APIs, not scraping. General search engines
ship behind a config switch, default off.

- **Query egress firewall** (load-bearing control): queries are built
  deterministically from pack+version (`"{product} {version} {check.class}"`),
  pass through an allowlist of token shapes, and are rejected if they contain the
  engagement host, any alias, in-scope paths, or captured tokens. Every outgoing
  query is logged to `.ledger/research-queries.jsonl` and audited. Success: zero
  target-identifying tokens in the log, ever.
- Trust ranking: T1 (NVD/GHSA/vendor/RFC) and T2 (PortSwigger research, OWASP)
  may support a mechanism claim; T3 (writeups, PoC repos) are leads only.
  Retrieved intelligence can propose a probe but can never substitute for a
  locally reproduced differential: a finding whose only evidence is a citation is
  rejected at `record_finding` (enforced by the WS1 verifier).
- `research_to_probe` converts an advisory into a candidate precursor
  (`confidence ≤ 0.5, source: "research"`); Kryptex still must direct a local
  differential test. Metric: share of research-sourced precursors locally
  confirmed.

### WS6 — Defense-signal taxonomy and bounded access-control verification

Replace the single "defense signal ends the family" rule (which today exists
only on the auth path anyway) with a classifier in the engine post-turn pass:

- **Hard-stop classes** (keep current behavior, correctly): CAPTCHA/interactive
  challenge, explicit WAF block page, escalating 429, lockout. No evasion, ever.
- **Information classes**: plain 401/403/404 on a resource is access-control
  information, not a defense. Permit a **bounded, per-path, rate-limited
  characterization sequence** (Fable's design): method differential
  (GET/HEAD/OPTIONS/POST); path-equivalence checks (canonical forms: trailing
  slash, case, duplicate slashes, dot-segments) for recognizing
  proxy/origin normalization gaps; one labeled header-trust probe each
  (forwarded/client-IP/host-override) against a clean control; vhost/origin
  differences where scope permits; a small curated backup/extension set on
  already-known paths only; cached-copy check. Every step rate-limited via
  `request_policy`, logged to `tested_technique_log`, with explicit decision
  rules (a different status/size/template is an anomaly, not bypass proof; a
  valid result requires the same protected capability and object under an
  unauthorized principal).
- Explicitly **not** included: wordlist content-discovery fuzzing, evasion of
  challenge pages. Astra's stricter variant — full comparison matrices only in
  owner-controlled fixtures, characterization-only on live targets — is the
  conservative default; per-program relaxation is an operator decision (D3).

### WS7 — Burp-parity browser instrumentation and support tools

Full implementation-ready designs (JSON schemas, bounds, metrics, test matrices)
are in [`CONSULT_DAYBREAK_INSTRUMENTATION.md`](CONSULT_DAYBREAK_INSTRUMENTATION.md);
the summary below is the commitment.

- **`BrowserExchangeRecorder`** (one per Chromium context, attached before first
  navigation): CDP `requestWillBeSent/responseReceived/loadingFinished(+Failed)`
  correlated by `(cdp_session_id, requestId, redirect_hop)`; headers + POST data
  + response bodies for XHR/fetch/document (2 MB bound) written through
  `_save_flow` into the existing `flows/flow-*.http` format; initiator
  attribution (page/frame/action_index mapping); redirect-parent linkage;
  explicit `body_state` completeness flags (`complete|not-applicable|too-large|
  buffer-evicted|retrieval-error|loading-failed|drain-timeout`); drain protocol
  before context close (network-quiet wait, bounded, fsync) so captures are
  never silently lost. Browser-origin and curl-origin traffic become
  replay-equivalent. Metric: XHR flows captured ÷ XHR observed → 1.0.
- **`flows/index.jsonl`**: collector-owned append-only capture index (never
  worker-trusted) enabling the history tool; opaque authenticated cursor on
  `(captured_at_ns, exchange_id)`.
- **`exchange_history`** query tool: the proxy-history view (AND-combined
  filters: method/status/content-type/size/URL-substring/resource-type,
  paginated, no bodies or secret values returned) — Burp-style triage for the
  worker and the operator; `flow_read` stays the bounded detail view.
- **`browser_intercept`**: one bounded rule at a time (same override surface as
  `flow_replay`), scope-enforced and rate-limited; modified traffic is marked
  distinctly from baseline observations (Astra).
- **Storage inspection**: cookies/localStorage/sessionStorage metadata only
  (names, attributes, sizes, partitioning); values rendered `[REDACTED]` —
  Daybreak's note adopted: do not emit value hashes, low-entropy values are
  guessable.
- **WebSockets**: stay force-closed until the full gate passes — program-profile
  enablement, handshake translated to HTTP-equivalent scope checks, passive-only
  observation (no send API), 4-connection/200-frame/1 MB-per-connection/64 KB
  per-frame/60 s caps, text redaction + binary-as-sha256, direction/timestamp
  bookkeeping, close-on-excess, incomplete-instrumentation ⇒ close not observe.
- **Support tools** (Daybreak schemas, names as designed):
  `verify_finding` — the WS1 differential harness as a worker-facing read-only
  tool; re-parses capture bytes (never trusts index metadata), verdicts
  `supported|visible-but-unstable|no-visible-difference|invalid-control|
  inconclusive`;
  `technology_fingerprint` — consolidates markers from saved exchanges into
  structured stack identification, reports conflicting versions rather than
  choosing one (feeds WS4 pack matching);
  `js_endpoint_harvest` — bounded route extraction from saved JS bundles via the
  existing local regex machinery; labels candidates with scope state, never
  auto-adds surface rows;
  `graphql_introspect` — exactly one fixed depth-bounded introspection POST
  through the normal scoped/authenticated transports, no arbitrary query text;
  `session_token_decode` — JWS structure decode only (no verification, no
  algorithm selection, identity claims redacted);
  `callback_listener` — lease-based confirmation listener on an operator-owned
  HTTPS origin (fixed 204, body digest not body, keyed source fingerprint, ≤3
  events, ≤15 min TTL) for confirming documented server-side fetch integrations
  — enables Fable's SSRF stage-1 differential;
  `flow_replay_concurrent` — one serial baseline + N (2–8) barrier-synchronized
  byte-identical replays, pre-admitted only when the rate policy can schedule
  the batch inside a 500 ms window, dangerous methods/oversize bodies rejected,
  effectful and never supervisor-retryable — enables race/TOCTOU verification.
- `apk_extract_asset` generalization beyond `assets/` (bounded, audited) and a
  sourcemap analyzer close the remaining static-analysis gaps.

### WS8 — Exploration dynamics: coverage cells, strategy memory, breakers

- **Coverage model** (Astra): inventory = `surface × principal relationship ×
  operation × lifecycle state`, populated from documented and observed behavior.
  Progress = resolved coverage cells and answered questions — not finding counts
  or family-name churn. Feed cells into the stagnation counters in place of raw
  family-count pressure.
- **Exhaustion breakers** (Fable): negative-space prompts ("what is conspicuously
  absent — a missing auth check on a sibling endpoint, a header present
  everywhere except one route, an error that is too uniform"); re-fingerprint at
  a different layer (TLS/DNS/HTTP/JS) when stuck; auto-generate the
  state-machine transition-abuse matrix for every multi-step flow in the surface
  ledger; require `refuting_observation` on every hypothesis.
- **Strategy memory**: record each playbook/chain outcome (worked / dead end /
  blocked-with-reason) in a ledger; rotation iterates only untried-or-reopenable
  entries, never a blind carousel; two iterations without resolving a question ⇒
  change the question or surface for operator review.
- **Schedule**: ~50% strongest open evidence question, ~30% documented coverage
  gaps, ~20% hardening-guidance study reconciled against the system model.
- **Deadline-mode churn cap** (G-9): bound consecutive pivots that produce no
  resolved cell; make churn an operator-visible counter in health events.

---

## 3. Doctrine decisions requiring operator sign-off

| # | Decision | Recommendation |
|---|----------|----------------|
| D1 | Minimal-prompt contract: methodology reaches models via Kryptex per-turn injection (no contract bump) vs. a Kraude methodology pack (bumps `WORKER_PROMPT_CONTRACT_VERSION`, retires live sessions, changes the test contract) | Kryptex injection now; evaluate a Kraude pack after WS1–WS3 prove out |
| D2 | P3–P5 validation policy | Keep operator-triggered, add sampled automatic Astra spot-checks (e.g. 1 in 5) to measure worker under-claiming |
| D3 | 403/WAF posture | Adopt the WS6 taxonomy; characterization-only on live targets by default; per-program relaxation recorded in the operator program profile |
| D4 | Research egress | Enable Tier 1 structured APIs (NVD/GHSA/vendor advisories) with the egress firewall; keep search engines off until the firewall has audit history |
| D5 | New network surface (oob listener, burst replay, WebSocket-later) | Each integrates `request_policy` budgets and effectful-start markers before shipping; OOB listener only on operator-declared in-scope hosts |

---

## 4. Phased roadmap

**Phase 0 — integrity core (days):** WS1 Layers 1–2 (evidence package + mechanical
verifier + antifab quantitative-claim check); WS2 dual-coding + validator schema
split + rubric/rulings file + anchoring mitigation; WS6 defense classifier;
WS8 negative-space/refuting-observation prompts and strategy-memory ledger via
Kryptex context; wire dead skills content through the same injection path.

**Phase 1 — strategy engine (1–2 weeks):** precursor ledger + signal dictionary +
six staged chain playbooks + `chain_hypotheses` directive field; knowledge packs
for the first four classes + fingerprint matching + JIT injection; vendored
pinned VRT + audit rule; research Tier 1 + egress firewall + research-queries
audit; coverage cells + churn cap; CDP full-exchange capture + `browser_flows`
query tool.

**Phase 2 — tool surface (2–4 weeks):** remaining packs; `browser_intercept`;
`tech_fingerprint`, `js_route_harvest` (+sourcemap), `graphql_introspect`,
`jwt_decode`, `verify_finding`; `burst` replay mode; `oob_callback`;
storage inspection; apk asset generalization.

**Phase 3 — hardening and measurement:** admission-state machine + collector
receipts; WebSocket enablement behind the Astra gate; adjudicated severity corpus
and agreement dashboards; FFAR red-team drills; per-program 403-matrix policy.

---

## 5. Consultation provenance

| Model | Delivered | Notes |
|---|---|---|
| Astra (`gpt-6-astra` @ max) | Evidence standards + corrections, provenance/admission states, severity rule precedence, self-deception counter-table, coverage model, review layout, WS/intercept cautions | First attempt blocked by provider `cyber_policy`; retry under a defensive-QA framing succeeded. Declined live bypass recipes; contributed the owner-controlled conformance alternative |
| Claude Opus 5.5 | Artifact-bound evidence spec (package schema, 6-step verifier, chain-pinning), VRT+CVSS dual-coding table, boundary rulings, complete validator prompt rewrite, FFAR metric | Measured partial decline: declined offensive-autonomy/evasion design; the offered integrity/standards scope was accepted and delivered in full |
| Claude Fable 5.1 | Precursor/chain ledger, staged chain playbooks with per-class content, knowledge-pack schema + priorities, two-tier research + egress firewall, defense taxonomy, Burp-parity CDP design, exhaustion breakers | Full delivery; flagged that active-encoding ladders were scoped to recognition-of-normalization-gaps on known paths |
| OpenAI Daybreak | Full instrumentation designs: CDP `BrowserExchangeRecorder` lifecycle, `flows/index.jsonl` + `exchange_history`, `verify_finding` harness, and six support-tool schemas with bounds and metrics (see [`CONSULT_DAYBREAK_INSTRUMENTATION.md`](CONSULT_DAYBREAK_INSTRUMENTATION.md)) | Four attempts failed (2 stream idle timeouts, 2 `cyber_policy`); a fresh-context agent under the observability/QA framing delivered in full |

All four kept the authorized-frame boundary: hard-stop on challenge/evasion
remained unanimous; disagreement is only about how much characterization of plain
access-control responses is appropriate on live targets (D3).
