"use strict";
const $ = id => document.getElementById(id);
let workspace = null, selected = null, refreshInFlight = false, detailSequence = 0, casesSignature = "";
const labels = {plan:"Kryptex · Review plan",assessment:"Kraude · Evidence assessment",assessment_followup:"Kraude · Local follow-up",validation:"Codex · Independent validation",summary:"Kryptex · Closing review",requirements:"Local requirements",review:"Review"};
function node(tag, className, text) { const value = document.createElement(tag); if (className) value.className = className; if (text !== undefined) value.textContent = text; return value; }
function badge(value) { const known = ["supported","refuted","inconclusive","complete","running","failed","interrupted","draft","unreviewed"]; return node("span", "badge " + (known.includes(value) ? value : ""), value); }
function section(title) { const wrap = node("section", "detail-section"); wrap.append(node("h4", "detail-label", title)); return wrap; }
function list(values) { const ul = node("ul", "gap-list"); for (const value of values) ul.append(node("li", "", value)); return ul; }
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
  const all = workspace?.cases || [], visible = all.filter(item => (filter === "all" || item.status === filter) && (item.title + " " + item.id).toLocaleLowerCase().includes(query));
  $("case-count").textContent = visible.length;
  const signature = JSON.stringify([visible,selected,query,filter]); if (signature === casesSignature) return; casesSignature = signature;
  const box = $("case-list"); const focusedCase = document.activeElement?.dataset?.caseId; box.replaceChildren();
  if (!visible.length) {
    const empty = node("div", "empty-list"); empty.append(node("span", "empty-symbol", "◇")); empty.append(node("h3", "", all.length ? "No matching cases" : "Your first case starts here"));
    empty.append(node("p", "", all.length ? "Try another search or status filter." : "Create a case from the CLI, or explore the offline walkthrough."));
    if (!all.length) empty.append(node("code", "", "grypton demo")); box.append(empty); return;
  }
  for (const item of visible) {
    const button = node("button", "case-item" + (item.id === selected ? " selected" : "")); button.type = "button"; button.dataset.caseId = item.id; button.setAttribute("aria-pressed", String(item.id === selected));
    const topline = node("div", "case-topline"); topline.append(node("span", "case-id", "CASE / " + item.id.slice(-10).toUpperCase())); if (item.mode === "mock") topline.append(node("span", "mock", "MOCK")); button.append(topline);
    button.append(node("div", "case-title", item.title)); const meta = node("div", "case-meta"); meta.append(badge(item.status),node("span", "", item.evidence_count + " artifact" + (item.evidence_count === 1 ? "" : "s")),node("span", "", item.verdict)); button.append(meta);
    button.addEventListener("click", () => { selected = item.id; renderCases(); loadDetail(); }); box.append(button);
    if (focusedCase === item.id) button.focus({preventScroll:true});
  }
}
function renderDetail(data) {
  const box = $("detail"); box.replaceChildren(); const runs = data.runs || [], run = runs.at(-1), stages = run?.stages || {};
  const heading = node("div", "detail-heading"); heading.append(node("span", "detail-eyebrow", "CASE / " + data.id.slice(-10).toUpperCase()),badge(data.status)); box.append(heading,node("h3", "detail-title", data.title),node("p", "detail-claim", data.claim));
  if (run?.mode === "mock") box.append(node("p", "note", "MOCK REVIEW · No models were called. This walkthrough cannot validate a finding."));
  if (data.review_stale) box.append(node("p", "note", "EVIDENCE CHANGED · The previous review below is historical. Start a new review of the updated evidence."));
  const evidence = section("ATTACHED EVIDENCE");
  for (const item of data.evidence) { const entry = node("div", "artifact"), copy = node("div", "", item.name); copy.append(node("small", "", item.id + " · " + item.sha256.slice(0,16) + "…")); entry.append(node("span", "artifact-icon", "▤"),copy); evidence.append(entry); }
  if (!data.evidence.length) evidence.append(node("p", "detail-text", "No artifacts attached yet.")); box.append(evidence);
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
  if (run?.error) { const error = section("REVIEW ERROR"); error.append(node("p", "detail-text", run.error)); box.append(error); }
  const resources = run?.resources || []; if (resources.length) { const area = section("LOCAL REQUIREMENTS"); area.append(list(resources.map(item => item.kind.replaceAll("_"," ") + " · " + item.status + " · " + (Array.isArray(item.detail) ? item.detail.join(", ") : item.detail)))); box.append(area); }
  const action = section("CONTINUE IN THE CLI"); let command;
  if (data.status === "running") command = "grypton stop " + data.id;
  else if (["failed","interrupted"].includes(data.status)) command = "grypton resume " + data.id + (run?.mode === "mock" ? " --mock" : "");
  else if (!data.evidence.length) command = "grypton evidence add " + data.id + " /path/to/evidence.txt";
  else if (data.status === "draft") command = "grypton review " + data.id + " --dry-run";
  else command = "grypton report " + data.id;
  action.append(node("code", "detail-command", command)); box.append(action);
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
    for (const key of ["total","running","supported","inconclusive"]) $("count-" + key).textContent = workspace.counts[key];
    $("nav-count").textContent = workspace.counts.total;
    if (!$("team").children.length) renderModels(workspace.models);
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
