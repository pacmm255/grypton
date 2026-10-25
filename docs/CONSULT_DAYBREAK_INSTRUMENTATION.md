# Instrumentation Review: Grypton Assessment Tooling

## Review basis

This design preserves the platform’s existing safety boundaries: every outbound target request remains subject to `check_url_scope`, exact-origin session binding, private mandatory-header resolution, and the shared rate bucket. Evidence stays private and redacted, and tool output is evidence for independent review rather than an automatic finding.

The present implementation already provides the right integration points: `_save_flow` writes a metadata line followed by `REQUEST` and `RESPONSE` sections (`/root/grypton/grypton/tools.py:1025`); the MCP registry and restart-safety classification live in `/root/grypton/grypton/toolserver.py:762` and `:1268`; and `request_policy.enforce_rate_limit` serializes shared per-engagement buckets (`/root/grypton/grypton/request_policy.py:430`). The main observability gap is that `browse` records the final DOM as one response, while `browser_workflow` records only URL/method/status rows with empty bodies (`/root/grypton/grypton/tools.py:4189` and `:10163`).

## 1. Priority table

| Priority | Improvement | Why now | Dependency / rollout gate |
|---|---|---|---|
| P0 | Shared CDP `BrowserExchangeRecorder` for `browse`, authenticated browser requests, login flows, and workflows | Missing XHR/fetch/document bodies make browser evidence incomplete and weaken every later analyzer. | Land capture parser/writer tests first; preserve scope routing and redaction. |
| P0 | Structured, paginated `exchange_history` query | Current `proxy_flows` is only reverse file scan plus substring/limit, so analysts cannot triage proxy-style history reliably. | Recorder metadata/index format; backward-compatible parsing of old flows. |
| P0 | `verify_finding` differential harness | Converts ad hoc comparisons into reproducible positive/control/replay evidence without claiming causation. | Complete response captures and a strict flow parser. |
| P1 | Bounded concurrent replay | Directly supports vendor-requested idempotency and duplicate-submission checks; it is effectful and must follow capture correctness. | Operator capability flag, rate admission, supervisor no-replay classification. |
| P1 | Fixed-query GraphQL introspection | High-value structured surface discovery with one auditable request. | Existing HTTP/auth transports; explicit program permission where required. |
| P1 | JS-bundle endpoint harvester | Converts already-saved bundles into candidate routes without additional traffic. | Flow body reader and local regex/tokenizer bounds. |
| P2 | Technology fingerprint summarizer | Useful prioritization, but lower evidentiary value than raw exchanges and differentials. | Versioned signature rules and confidence/evidence model. |
| P2 | JWT/session-token structure decoder | Useful for session analysis, but local-only and intentionally non-verifying. | Private token lookup and claim redaction policy. |
| P2 | Controlled callback listener | Valuable for documented integration data-flow confirmation, but requires separately operated callback infrastructure and ownership controls. | Operator-configured TLS callback origin, lease store, retention policy. |

Release P0 behind capture-format versioning, then ship read-only P1/P2 analyzers independently. Enable network-effecting GraphQL, callback leases, and concurrent replay only after audit, policy, and restart-safety tests pass.

## 2A. Browser network observability: recorder and capture lifecycle

Create one `BrowserExchangeRecorder` per Chromium context and attach CDP `Network` listeners before the first navigation. Attach every page/popup target (and flattened child targets when Chromium exposes an out-of-process frame); service workers remain blocked. Correlate by `(cdp_session_id, requestId, redirect_hop)`, not URL or Playwright object identity.

Event handling:

1. `requestWillBeSent`: allocate an exchange ID; retain method, URL, bounded headers, `postData`, resource type, wall/monotonic timestamps, `frameId`, `loaderId`, and sanitized `initiator`. If `redirectResponse` exists for the reused request ID, finalize the preceding hop and set the new record’s `redirect_parent_exchange_id`.
2. `responseReceived`: add status/status text, protocol, MIME type, response headers, remote address, cache/service-worker indicators, and timing. `requestWillBeSentExtraInfo`/`responseReceivedExtraInfo` may improve header fidelity but must not be required for completeness.
3. `loadingFinished`: record encoded length. For `Document`, `XHR`, and `Fetch`, retrieve `Network.getResponseBody` only when declared and encoded sizes are within 2,000,000 bytes. Enable Network with a 2 MB per-resource buffer. Decode base64 defensively, redact before persistence, and mark the body complete only when retrieval and decoding finish.
4. `loadingFailed`: finalize error text/type and cancellation/blocking state without inventing an HTTP response.

Each exchange is written atomically as mode `0600` through an extended `_save_flow`, retaining the existing layout:

```text
### GRYPTON FLOW {one-line JSON}
### REQUEST
METHOD URL
headers

body

### RESPONSE
status line
headers

body
```

Metadata should include `format_version`, `exchange_id`, `browser_context_id`, `page_id`, `frame_id`, `resource_type`, start/end time, request/response byte counts, content type, status, failure, redirect parent, and completeness flags. Use `body_state` values `complete`, `not-applicable`, `too-large`, `buffer-evicted`, `retrieval-error`, `loading-failed`, or `drain-timeout`; include `body_sha256` only for the exact captured body. Bound request bodies to 1 MB, each response body to 2 MB, each header block to 256 KB/256 fields, and initiator stacks to eight frames. Oversize data is omitted, never partially presented as complete.

Initiator attribution combines CDP’s initiator type/stack with Grypton context: map `frameId` to page/frame URL, assign a monotonically increasing workflow `action_index` immediately before each action, and record `page_id`, `frame_id`, `loader_id`, and `action_index`. Navigation requests caused by a redirect additionally carry the parent exchange ID. Stack entries retain only redacted URL, function name, line, and column.

Before context close, stop starting actions, wait for 250 ms network quiet subject to a 2-second and overall-tool deadline, retrieve all eligible finished bodies, then finalize every still-pending record with `drain-timeout`. Flush and fsync capture/index records before `context.close()`. This replaces the current fixed 50 ms wait in the authenticated browser path and prevents closure from racing body retrieval.

## 2B. Browser history, storage metadata, and WebSocket gate

Add a read-only MCP tool `exchange_history`. Its input schema is:

```json
{
  "type":"object", "additionalProperties":false,
  "properties":{
    "methods":{"type":"array","maxItems":10,"uniqueItems":true,"items":{"type":"string","pattern":"^[A-Z]{1,20}$"}},
    "statuses":{"type":"array","maxItems":20,"uniqueItems":true,"items":{"type":"integer","minimum":100,"maximum":599}},
    "content_type_contains":{"type":"string","maxLength":128},
    "min_response_bytes":{"type":"integer","minimum":0,"maximum":2000000},
    "max_response_bytes":{"type":"integer","minimum":0,"maximum":2000000},
    "url_contains":{"type":"string","maxLength":512},
    "resource_types":{"type":"array","maxItems":8,"uniqueItems":true,"items":{"enum":["Document","XHR","Fetch","Other"]}},
    "complete_only":{"type":"boolean"},
    "cursor":{"type":"string","maxLength":256},
    "limit":{"type":"integer","minimum":1,"maximum":100,"default":25}
  }
}
```

The output is `{items:[{exchange_id,captured_at,duration_ms,method,url,status,content_type,request_bytes,response_bytes,resource_type,page_id,frame_id,action_index,redirect_parent_exchange_id,body_state,failed,flow}], next_cursor, has_more, scanned}`. It never returns bodies or secret header values. Validate `min <= max`; combine filters with AND. Cursor ordering is `(captured_at_ns, exchange_id)` descending and the cursor is an authenticated opaque encoding, so concurrent appends neither duplicate nor skip older rows.

Have `_save_flow` append the safe fields to a locked `flows/index.jsonl`; do not trust worker-written indexes. Resolve every flow through `_flow_path`, reject symlinks, and re-parse the capture metadata when serving a row. Build a bounded legacy page by scanning old files only when no index row exists. This yields a commercial proxy-style history while `flow_read` remains the bounded detail view.

For cookie and web-storage inventory, add metadata to the terminal context record, not values. Cookies expose only `{name,domain,path,expires,httpOnly,secure,sameSite,partitionKey_present,value_bytes}`. `localStorage` and `sessionStorage` expose `{origin,name,value_bytes}`. Values are always the literal `"[REDACTED]"` if a common display schema requires a value field; do not emit hashes because low-entropy values are guessable. Derive metadata in the trusted process from `context.cookies()` and a page evaluation that returns keys and UTF-8 lengths only. Reuse current limits: 200 cookies, 100 entries per storage area, 512-character keys, 65,536-character values, and 1 MB total. Keep exact values solely in the existing private credential store.

WebSockets remain closed by default. Permit observation only when all gates pass:

- The program profile explicitly enables observation; translate the `ws`/`wss` handshake to its HTTP(S) equivalent and pass full URL/path scope, exact authenticated-origin, proxy, mandatory-header, and shared rate-bucket checks. Reject redirects unless each hop is rechecked.
- Observation is passive: no tool API for sending frames. Cap 4 connections/context, 200 frames/connection, 1 MB total/connection, 64 KB/frame, and 60 seconds; close immediately on any excess.
- Redact text with credential, policy, cookie, token, and identity needles before writing. For binary frames store only byte length and SHA-256; never payload bytes.
- Record `{connection_id,handshake_exchange_id,sequence,direction,timestamp,opcode,bytes,sha256,truncated}` and close/finalize during the same drain phase. If instrumentation is not attached before the first frame, mark incomplete and close rather than silently observing.

## 3. Authenticated-request differential harness

Register a read-only `verify_finding` helper with this input schema:

```json
{
  "type":"object", "additionalProperties":false,
  "required":["positive_exchange_id","control_exchange_id","replay_exchange_ids","changed_variable"],
  "properties":{
    "positive_exchange_id":{"type":"string","pattern":"^flow-[0-9]+$","maxLength":80},
    "control_exchange_id":{"type":"string","pattern":"^flow-[0-9]+$","maxLength":80},
    "replay_exchange_ids":{"type":"array","minItems":1,"maxItems":2,"uniqueItems":true,"items":{"type":"string","pattern":"^flow-[0-9]+$","maxLength":80}},
    "changed_variable":{
      "type":"object","additionalProperties":false,"required":["location","name"],
      "properties":{
        "location":{"enum":["method","url_path","query","header","body_form","body_json_pointer","body_text"]},
        "name":{"type":"string","minLength":1,"maxLength":512}
      }
    },
    "selected_response_headers":{"type":"array","maxItems":16,"uniqueItems":true,"items":{"type":"string","pattern":"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$"}}
  }
}
```

`body_json_pointer` uses RFC 6901 syntax; `name` is the query/form/header name, pointer, or the literal labels `method`, `path`, or `body`. Raw expected values are deliberately not accepted. The helper compares their canonical presence/value internally and returns only equality and digests. It rejects duplicate IDs, malformed/legacy-unparseable captures, non-HTTP exchanges, incomplete bodies, redacted/ambiguous declared variables, and exchanges whose method/origin/path family cannot form a meaningful control.

For every exchange, re-parse bytes from the `.http` file rather than trusting index metadata. Produce:

```json
{
  "verdict":"supported|visible-but-unstable|no-visible-difference|invalid-control|inconclusive",
  "declared_change":{"location":"...","name":"...","visible":true},
  "request_comparison":{"only_declared_variable_changed":true,"unexpected_changes":[]},
  "exchanges":[{
    "id":"flow-...","role":"positive|control|replay",
    "response_digest":{"status":200,"body_sha256":"64 hex","body_bytes":1234,
      "selected_headers":{"content-type":{"present":true,"sha256":"64 hex"}}}
  }],
  "positive_vs_control":{"different":true,"dimensions":["status","body_sha256"]},
  "replay_stability":{"stable":true,"matching_replays":2,"total_replays":2},
  "limitations":[]
}
```

Canonicalize header names case-insensitively, preserve duplicate response header values in wire order, parse status from the response start line, and hash the exact stored response-body bytes. Length is that same body’s byte length. A difference is **visible** only when (a) the request projection changes at the declared location, (b) no other request component changes, and (c) the positive response vector differs from control. It is **stable** only when every replay response vector exactly equals the positive vector. This proves an observed differential, not authorization impact or causality.

Implementation sketch: add `_parse_http_flow(path, max_bytes)` and canonical request/response projections in `tools.py`; implement `verify_finding(workspace, args)` using `_flow_path`, `hashlib.sha256`, `urllib.parse`, and bounded JSON/form parsing; expose `_verify_finding` and its schema in `toolserver.REGISTRY`; add `verify_finding` to `_RESTART_SAFE_READ_ONLY_TOOLS`. Tests should mutate on-disk metadata to prove it is ignored, cover duplicate headers/UTF-8 bytes, redacted variables, truncated captures, one/two replays, and a concurrent file append.

## 4A. Support tools: passive surface analysis and GraphQL

### `technology_fingerprint`

Input schema: `{"type":"object","additionalProperties":false,"required":["exchange_ids"],"properties":{"exchange_ids":{"type":"array","minItems":1,"maxItems":100,"uniqueItems":true,"items":{"type":"string","pattern":"^flow-[0-9]+$"}},"max_components":{"type":"integer","minimum":1,"maximum":50,"default":25}}}`.

Output `data`: `{components:[{name,category,confidence,versions,evidence:[{exchange_id,location,marker}]}], conflicts:[], exchanges_scanned, bytes_scanned, truncated}`. `marker` is a rule label, never copied secret text. Bound input to 32 MB total parsed data and 200 evidence rows. Implementation: parse saved response headers/bodies; apply versioned declarative signatures for server headers, cookies by name only, HTML meta/generator tags, framework asset paths, and bounded JS globals. Combine independent signals, cap confidence, and report conflicting versions rather than choosing one. No network access and no shelling out.

### `js_endpoint_harvest`

Input schema: `{"type":"object","additionalProperties":false,"required":["exchange_ids"],"properties":{"exchange_ids":{"type":"array","minItems":1,"maxItems":20,"uniqueItems":true,"items":{"type":"string","pattern":"^flow-[0-9]+$"}},"url_base":{"type":"string","maxLength":8192},"max_routes":{"type":"integer","minimum":1,"maximum":500,"default":200}}}`.

Output `data`: `{routes:[{value,kind,source_exchange_id,byte_offset,scope_state,confidence}], bundles_scanned, bytes_scanned, truncated, rejected_candidates}`. Hard-limit each source to 2 MB and the call to 20 MB; strings/routes are at most 8,192 characters. Implementation: require JavaScript MIME type or `.js` URL, then run the existing bounded local byte-regex machinery over string literals and recognizable `fetch`, XHR, Axios, router, source-map, and GraphQL-operation patterns. Decode only simple quoted escapes, resolve relative paths against the exchange URL or `url_base`, deduplicate canonical candidates, and call `check_url_scope` only to label them. Never evaluate JS, follow source maps, fetch candidates, or automatically add attack-surface rows.

### `graphql_introspect`

Input schema: `{"type":"object","additionalProperties":false,"required":["url"],"properties":{"url":{"type":"string","maxLength":8192},"credential":{"type":"string","maxLength":64},"timeout":{"type":"integer","minimum":5,"maximum":60,"default":30},"max_types":{"type":"integer","minimum":1,"maximum":200,"default":100},"max_fields_per_type":{"type":"integer","minimum":1,"maximum":200,"default":100}}}`.

Output `data`: `{enabled,flow,queries:[{name,return_type,args:[{name,type,default_value}]}],mutations:[...],subscriptions:[...],types:[{name,kind,fields:[{name,type,args}]}],schema_sha256,truncated,errors}`. Cap operations at 500, arguments at 50/field, names at 512 characters, and the captured response at 2 MB.

Implementation: send exactly one fixed, depth-bounded standard introspection POST through `http_request` or `authenticated_http_request`; those transports perform scope, exact-origin authentication, mandatory-header, rate, redirect, and capture enforcement. Parse JSON without executing returned content, omit descriptions by default, sort deterministically, and distinguish “introspection disabled” from transport/schema errors. Do not accept arbitrary GraphQL text, aliases, batching, GET fallback, or retry. Require an operator/program capability where the program rules condition introspection.

All three handlers return the normal `{ok,summary,data}` envelope. The first two belong in `_RESTART_SAFE_READ_ONLY_TOOLS`; GraphQL remains effectful and receives the pre-dispatch durable marker.

## 4B. Support tools: tokens, controlled callbacks, and concurrency

### `session_token_decode`

Input schema uses `oneOf`: either `{"token":{"type":"string","minLength":1,"maxLength":16384}}` or `{"credential":{"type":"string","maxLength":64},"token_name":{"type":"string","maxLength":512}}`; all variants set `additionalProperties:false`. Output `data` is `{format:"JWS",header:{...},payload:{...},signature_present,verified:false,temporal:{issued_at,not_before,expires_at,expired},redactions:[],warnings:[]}`. Bound decoded header and payload to 64 KB each, 128 claims, nesting depth 8, and 1,000 aggregate scalar values.

Implementation: for an alias, load the named token only inside the trusted process; for direct input, rely on the existing audit redaction for the `token` key. Split exactly three base64url segments, strictly decode and parse JSON objects, discard signature bytes, and never select algorithms or keys. Redact token-like claim values and identity claims (for example `sub`) before output; normalize only numeric dates. Reject JWE and malformed/oversize input. Always state that decoding is not verification. This tool is restart-safe and local-only.

### `callback_listener`

Input schema: `{"type":"object","additionalProperties":false,"required":["action"],"properties":{"action":{"enum":["issue","poll","close"]},"lease_id":{"type":"string","pattern":"^[A-Za-z0-9_-]{20,80}$"},"ttl_seconds":{"type":"integer","minimum":30,"maximum":900,"default":300},"expected_method":{"enum":["GET","POST"]},"max_events":{"type":"integer","minimum":1,"maximum":10,"default":3}}}`; require `lease_id` for poll/close. Output `data` is `{lease_id,callback_url,expires_at,confirmed,events:[{received_at,method,body_bytes,body_sha256,header_names,source_fingerprint}],closed}`.

Implementation: use only an operator-configured HTTPS callback origin whose DNS/TLS ownership is proven and whose exact URL is in scope; do not accept a host from the caller. `issue` creates an unguessable, one-purpose lease in private state. A separately supervised minimal listener returns a fixed `204`, performs no redirects/reflection, and records at most 64 headers/32 KB, a 64 KB body digest (not body), three events, and a 15-minute lifetime. Store a keyed source-address fingerprint rather than the address. Polling confirms only a matching nonce/method received after issuance. The tool never triggers the vendor request; it only confirms a documented integration the analyst configured. Issue/close are effectful; poll is restart-safe.

### `flow_replay_concurrent`

Input schema: `{"type":"object","additionalProperties":false,"required":["flow_id","concurrency","purpose"],"properties":{"flow_id":{"type":"string","pattern":"^flow-[0-9]+$"},"concurrency":{"type":"integer","minimum":2,"maximum":8},"purpose":{"enum":["idempotency","double-submission"]},"credential":{"type":"string","maxLength":64},"timeout":{"type":"integer","minimum":5,"maximum":30,"default":20}}}`. Output `data` is `{request_sha256,baseline:{exchange_id,status,body_sha256,body_bytes,duration_ms},runs:[...],start_spread_ms,policy_min_spacing_ms,near_simultaneous,signature_counts,duplicate_successes,limitations}`.

Implementation: require an operator-set concurrent-replay capability. Parse one capture; reject redirects, `DELETE`/`CONNECT`/`TRACE`, bodies over 1 MB, redaction placeholders, or any override. Run one completed baseline, then use a barrier and `ThreadPoolExecutor` for exactly N byte-identical requests. Every worker re-enters the ordinary scoped/authenticated transport so mandatory headers and the shared rate lock apply. Pre-admit N only when the configured rate can schedule them inside a 500 ms window; otherwise do not send the batch. Capture every response separately and report start timestamps and digest multiplicities, not a vulnerability verdict. Maximum traffic is `1 + N` requests, once per call; it is effectful and never supervisor-retryable.

## 5. Tool bounds and success metrics

| Tool | Enforced bounds | Release / operational success metric |
|---|---|---|
| `verify_finding` | Exactly 1 positive, 1 control, and 1–2 replay IDs; ≤4 captures; ≤2 MB response body/capture; ≤16 selected headers; no incomplete/redacted declared variable. | On a corpus containing stable, unstable, no-difference, extra-request-delta, malformed, and truncated cases: 100% expected verdicts; altering metadata alone never alters a digest; no raw selected-header value is returned. |
| `technology_fingerprint` | 1–100 exchanges; 32 MB total parsed; ≤50 components and ≤200 evidence rows; versioned fixed rules only. | ≥95% precision and ≥90% recall on labeled framework/server fixtures, with every component linked to at least one exchange marker and zero network calls. |
| `js_endpoint_harvest` | 1–20 bundles; ≤2 MB/source and 20 MB/call; ≤500 routes; ≤8,192 characters/candidate; no evaluation or fetch. | ≥95% recall for literal routes in a fixture suite, zero executable-JS side effects, zero outbound requests, and deterministic output across repeated runs. |
| `graphql_introspect` | One fixed POST, no retry/batch/arbitrary query; 5–60 seconds; ≤2 MB response; ≤200 types, 200 fields/type, 500 operations, and 50 args/field. | Against a known schema, all query/mutation names and field signatures within configured limits match the reference; transport audit shows exactly one policy-compliant request and one flow. |
| `session_token_decode` | One token ≤16 KB; exactly 3 JWS segments; decoded header/payload ≤64 KB each; ≤128 claims, depth 8, and 1,000 scalar values; no JWE/signature verification. | RFC/base64url fixtures decode deterministically; malformed/oversize/JWE fixtures fail closed; output always says `verified:false`, contains no signature bytes, and redacts configured identity/token-like claims. |
| `callback_listener` | Operator-fixed owned HTTPS origin; ≤10 active leases/engagement; TTL 30–900 seconds; ≤3 stored events/lease; ≤64 headers/32 KB and body digest for ≤64 KB; fixed 204 response. | End-to-end controlled test confirms exactly the leased request with timestamp/method/digest, rejects random/expired nonces, retains no body or raw source address, and performs no redirect or outbound fetch. |
| `flow_replay_concurrent` | Explicit operator capability; one baseline plus N=2–8; one exact saved request; ≤1 MB body; timeout 5–30 seconds; admitted batch window ≤500 ms; shared rate policy always applied; dangerous methods/redacted captures rejected. | Instrumented integration test proves all transmitted request digests are identical, actual starts stay within the admitted window, observed spacing never violates the configured bucket, every response has a capture, and an impossible rate/window causes zero batch requests. |

Cross-cutting acceptance criteria: schemas reject unknown properties; capture/analyzer outputs pass the existing secret and identity redactors; files are private regular files opened without symlink following; every network tool produces an effectful-start audit marker and durable flow; every local/query tool is explicitly listed restart-safe; and fault injection before context close leaves either complete captures or an explicit completeness reason, never silent loss.