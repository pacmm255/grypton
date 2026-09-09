"use strict";
const $ = id => document.getElementById(id);
let workspace = null, labData = null, auditData = null, selected = null, refreshInFlight = false, detailSequence = 0, casesSignature = "";
const labels = {plan:"Kryptex · Review plan",assessment:"Kraude · Evidence assessment",assessment_followup:"Kraude · Local follow-up",validation:"Codex · Independent validation",summary:"Kryptex · Closing review",requirements:"Local requirements",review:"Review"};
function node(tag, className, text) { const value = document.createElement(tag); if (className) value.className = className; if (text !== undefined) value.textContent = text; return value; }
function badge(value) { const known = ["supported","refuted","inconclusive","complete","running","failed","interrupted","draft","unreviewed","candidate","validating","outdated"]; return node("span", "badge " + (known.includes(value) ? value : ""), value); }
function section(title) { const wrap = node("section", "detail-section"); wrap.append(node("h4", "detail-label", title)); return wrap; }
function list(values) { const ul = node("ul", "gap-list"); for (const value of values) ul.append(node("li", "", value)); return ul; }
function stat(label, value) { const item = node("div", "workspace-stat"); item.append(node("strong", "", String(value)),node("span", "", label)); return item; }
async function request(path) { const response = await fetch(path, {cache:"no-store",credentials:"same-origin",signal:AbortSignal.timeout(12000)}); if (!response.ok) { const value = await response.json().catch(() => ({})); throw new Error(value.error || "Could not load workspace (" + response.status + ")."); } return response.json(); }
function renderModels(models) {
  const team = $("team"); team.replaceChildren();
  const friendly = {worker:"GLM-5.3",manager:"Muse Spark 1.3 Contributor",validator:"GPT-6 Astra"};
  const plans = {worker:"Z.AI Coding Plan",manager:"OpenCode Go",validator:"Codex"};
  for (const [role, model] of Object.entries(models)) {
    const card = node("article", "team-card"); card.append(node("span", "role-icon " + role, role === "worker" ? "K" : role === "manager" ? "◇" : "✓"));
    const copy = node("div", "role-copy"), title = node("div", "role-title", model.name); title.append(node("span", "role-tag", role)); copy.append(title);
    copy.append(node("div", "role-model", friendly[role] || model.model)); const provider = node("div", "role-provider", plans[role]); provider.append(node("span", "role-effort", "· " + model.effort)); copy.append(provider);
    card.title = model.qualified; card.append(copy); team.append(card);
  }
}
function renderCases() {
  const query = $("search").value.trim().toLocaleLowerCase(), filter = $("filter").value;
  const all = workspace?.cases || [], visible = all.filter(item => (filter === "all" || item.status === filter) && ([item.target,item.title,item.id,item.claim].join(" ")).toLocaleLowerCase().includes(query));
  $("case-count").textContent = visible.length;
  const signature = JSON.stringify([visible,selected,query,filter]); if (signature === casesSignature) return; casesSignature = signature;
  const box = $("case-list"); const focusedCase = document.activeElement?.dataset?.caseId; box.replaceChildren();
  if (!visible.length) {
    const empty = node("div", "empty-list"); empty.append(node("span", "empty-symbol", "◇")); empty.append(node("h3", "", all.length ? "No matching cases" : "Your first case starts here"));
    empty.append(node("p", "", all.length ? "Try another search or status filter." : "Create an engagement from the CLI, or inspect the fixed validation lab."));
    if (!all.length) empty.append(node("code", "", "grypton init \"project.example\"")); box.append(empty); return;
  }
  for (const item of visible) {
    const button = node("button", "case-item" + (item.id === selected ? " selected" : "")); button.type = "button"; button.dataset.caseId = item.id; button.setAttribute("aria-pressed", String(item.id === selected));
    const topline = node("div", "case-topline"); topline.append(node("span", "case-id", "ENG / " + item.id.toUpperCase())); if (item.mode === "mock") topline.append(node("span", "mock", "MOCK")); button.append(topline);
    button.append(node("div", "case-title", item.target || item.title)); const meta = node("div", "case-meta"); meta.append(badge(item.status),node("span", "", item.evidence_count + " artifact" + (item.evidence_count === 1 ? "" : "s")),node("span", "", item.finding_count + " finding" + (item.finding_count === 1 ? "" : "s"))); button.append(meta);
    button.addEventListener("click", () => { selected = item.id; renderCases(); loadDetail(); }); box.append(button);
    if (focusedCase === item.id) button.focus({preventScroll:true});
  }
}
function renderDetail(data) {
  const box = $("detail"); box.replaceChildren(); const runs = data.runs || [], run = runs.at(-1), stages = run?.stages || {};
  const heading = node("div", "detail-heading"); heading.append(node("span", "detail-eyebrow", "ENGAGEMENT / " + data.id.toUpperCase()),badge(data.status)); box.append(heading,node("h3", "detail-title", data.target || data.title),node("p", "detail-claim", data.claim));
  const workspaceStats = node("div", "workspace-stats"); workspaceStats.append(
    stat("messages", data.message_count), stat("instructions", data.standing_instruction_count),
    stat("observations", data.observation_count), stat("surface records", data.surface.length)); box.append(workspaceStats);
  if (run?.mode === "mock") box.append(node("p", "note", "MOCK REVIEW · No models were called. This walkthrough cannot validate a finding."));
  if (data.review_stale) box.append(node("p", "note", "EVIDENCE CHANGED · The previous review below is historical. Start a new review of the updated evidence."));
  const scopeValues = data.scope || {}, scopeRows = [];
  for (const key of ["in_scope","out_of_scope","only_severities","include_classes","exclude_classes","rules"]) if (scopeValues[key]?.length) scopeRows.push(key.replaceAll("_"," ") + " · " + scopeValues[key].join(", "));
  const scope = section("ENGAGEMENT SCOPE"); scope.append(node("p", "scope-type", "TYPE / " + (scopeValues.type || "auto").toUpperCase()));
  scope.append(scopeRows.length ? list(scopeRows) : node("p", "detail-text", "No additional scope labels are stored; analysis remains limited to supplied material.")); box.append(scope);
  const evidence = section("ATTACHED EVIDENCE");
  for (const item of data.evidence) { const entry = node("div", "artifact"), copy = node("div", "", item.name); copy.append(node("small", "", item.id + " · " + item.sha256.slice(0,16) + "…")); entry.append(node("span", "artifact-icon", "▤"),copy); evidence.append(entry); }
  if (!data.evidence.length) evidence.append(node("p", "detail-text", "No artifacts attached yet.")); box.append(evidence);
  if (data.surface.length) { const surface = section("SURFACE RECORDS"); for (const item of data.surface) { const row = node("div", "surface-row"); row.append(node("span", "surface-kind", item.category),node("span", "", item.text)); surface.append(row); } box.append(surface); }
  if (run?.events?.length) {
    const progress = section("REVIEW PROGRESS"), timeline = node("ol", "timeline");
    const latest = new Map(); for (const event of run.events) latest.set(event.stage,event);
    for (const [stage,event] of latest) { const li = node("li", "", (labels[stage] || stage) + " · " + event.status); li.append(node("small", "", event.detail)); timeline.append(li); } progress.append(timeline); box.append(progress);
  }
  if (stages.validation) {
    const verdict = stages.validation, validation = section("INDEPENDENT VERDICT"), title = node("div", "validation-title"); title.append(badge(verdict.verdict),node("span", "", "Severity: " + verdict.severity));
    validation.append(title,node("p", "detail-text", verdict.rationale));
    if (verdict.limitations.length) validation.append(node("h4", "detail-label", "LIMITATIONS"),list(verdict.limitations));
    if (verdict.remediation.length) validation.append(node("h4", "detail-label", "REMEDIATION"),list(verdict.remediation));
    validation.append(node("p", "note", "This verdict describes the supplied evidence. It does not establish live reproduction.")); box.append(validation);
  }
  if (stages.summary) { const summary = section("KRYPTEX SUMMARY"); summary.append(node("p", "detail-text", stages.summary.summary),list(stages.summary.next_steps)); box.append(summary); }
  if (data.findings.length) {
    const ledger = section("FINDING LEDGER");
    for (const finding of data.findings.slice().reverse()) {
      const card = node("article", "finding-card"), top = node("div", "finding-top"); top.append(node("span", "finding-id", finding.id),badge(finding.status)); card.append(top,node("h5", "", finding.title));
      const meta = node("p", "finding-meta", "Severity " + (finding.severity || "unknown") + " · " + finding.evidence_ids.length + " cited artifact" + (finding.evidence_ids.length === 1 ? "" : "s")); card.append(meta);
      if (finding.validation?.rationale) card.append(node("p", "detail-text", finding.validation.rationale)); ledger.append(card);
    }
    box.append(ledger);
  }
  if (run?.calls?.length) {
    const audit = section("MODEL CALL AUDIT"), table = node("div", "call-audit");
    for (const call of run.calls) { const row = node("div", "call-row"); row.append(node("span", "call-stage", call.stage),node("span", "", call.route.qualified),node("span", "", call.route.effort),node("span", "", call.duration_ms + " ms"),badge(call.status)); table.append(row); }
    audit.append(table,node("p", "note", "Inputs and outputs are represented by SHA-256 digests in state; raw provider prompts are not stored.")); box.append(audit);
  }
  if (run?.error) { const error = section("REVIEW ERROR"); error.append(node("p", "detail-text", run.error)); box.append(error); }
  const resources = [...(run?.resources || []),...(data.resource_events || [])]; if (resources.length) { const area = section("LOCAL REQUIREMENTS"); area.append(list(resources.slice(-20).map(item => item.kind.replaceAll("_"," ") + " · " + item.status + " · " + (Array.isArray(item.detail) ? item.detail.join(", ") : item.detail)))); box.append(area); }
  const action = section("CONTINUE IN THE CLI"); let command;
  if (data.status === "running") command = "grypton stop " + data.id;
  else if (["failed","interrupted"].includes(data.status)) command = "grypton resume " + data.id + " --review" + (run?.mode === "mock" ? " --mock" : "");
  else if (!data.evidence.length) command = "grypton evidence add " + data.id + " /path/to/evidence.txt";
  else if (data.status === "draft") command = "grypton review " + data.id + " --dry-run";
  else command = "grypton report " + data.id;
  action.append(node("code", "detail-command", command)); box.append(action);
}
function renderLab(data) {
  const box = $("lab-summary"); box.replaceChildren(); const intro = node("div", "lab-intro");
  intro.append(node("strong", "", data.scenario_count + " scenarios · " + data.turn_count + " evidence turns"),node("span", "", "sha256:" + data.suite_sha256.slice(0,16) + "…")); box.append(intro);
  const grid = node("div", "lab-grid"); for (const scenario of data.scenarios) { const card = node("article", "lab-card"); card.append(node("span", "lab-id", scenario.id),node("h3", "", scenario.title),node("p", "", scenario.turn_count + " turns · " + scenario.expected_transitions.join(" → "))); grid.append(card); } box.append(grid,node("code", "detail-command", "grypton lab verify"));
}
function renderAudit(data) {
  const box = $("integrity-summary"); box.replaceChildren();
  const passed = data.checks.filter(item => item.ok && !item.skipped).length;
  const active = data.checks.filter(item => !item.skipped).length;
  const intro = node("div", "integrity-intro"); intro.append(
    node("div", "integrity-score", passed + "/" + active),
    node("div", "", data.ok ? "Fork contract verified" : "Review failed checks"),
    badge(data.ok ? "complete" : "failed")); box.append(intro);
  const grid = node("div", "integrity-grid");
  for (const item of data.checks.filter(value => !value.skipped)) {
    const row = node("article", "integrity-check " + (item.ok ? "ok" : "fail"));
    row.append(node("span", "integrity-mark", item.ok ? "✓" : "!"));
    const copy = node("div"); copy.append(node("strong", "", item.check),node("small", "", item.detail)); row.append(copy); grid.append(row);
  }
  box.append(grid,node("p", "note", "Read-only structural audit · no model calls · no target interaction. Run grypton audit --auth for connector checks."));
}
async function loadDetail() {
  if (!selected) return; const id = selected, sequence = ++detailSequence;
  try { const data = await request("/api/cases/" + encodeURIComponent(id)); if (selected === id && sequence === detailSequence) renderDetail(data); }
  catch (error) { if (selected !== id || sequence !== detailSequence) return; $("detail").replaceChildren(node("p", "detail-text", error.message)); }
}
async function refresh() {
  if (refreshInFlight) return; refreshInFlight = true; $("refresh").disabled = true;
  try {
    const next = await request("/api/state"); const previous = workspace?.cases?.find(item => item.id === selected); workspace = next;
    for (const key of ["total","running","findings","validated"]) $("count-" + key).textContent = workspace.counts[key];
    $("nav-count").textContent = workspace.counts.total;
    if (!$("team").children.length) renderModels(workspace.models);
    if (!auditData) { auditData = await request("/api/audit"); renderAudit(auditData); }
    if (!labData) { labData = await request("/api/lab"); renderLab(labData); }
    if (!selected && workspace.cases.length) selected = workspace.cases[0].id;
    if (selected && !workspace.cases.some(item => item.id === selected)) { selected = null; detailSequence++; $("detail").replaceChildren(node("p", "detail-text", "The selected case is no longer available.")); }
    renderCases(); const current = workspace.cases.find(item => item.id === selected);
    if (current && (!previous || previous.updated_at !== current.updated_at)) await loadDetail();
    $("error-banner").hidden = true; $("connection-label").textContent = "Connected"; $("connection-dot").classList.remove("offline");
    $("updated").textContent = "Updated " + new Date().toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"});
  } catch (error) { $("error-banner").textContent = error.message + " Existing results may be out of date."; $("error-banner").hidden = false; $("connection-label").textContent = "Disconnected"; $("connection-dot").classList.add("offline"); }
  finally { refreshInFlight = false; $("refresh").disabled = false; }
}
$("search").addEventListener("input",renderCases); $("filter").addEventListener("change",renderCases);
$("refresh").addEventListener("click", () => { refresh(); if (selected) loadDetail(); });
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
function tick() { $("clock").textContent = new Date().toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"}); }
tick(); refresh(); setInterval(tick,30000); setInterval(() => { if (!document.hidden) refresh(); },5000);
