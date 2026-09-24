"use strict";

const $ = id => document.getElementById(id);
const el = (tag, cls, text) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
};

let state = null;
let selected = null;
let busy = false;

async function get(path) {
  const response = await fetch(path, {
    cache: "no-store",
    credentials: "same-origin",
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `HTTP ${response.status}`);
  }
  return response.json();
}

function badge(text) {
  const label = String(text || "unknown");
  const kind = label.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").slice(0, 40);
  return el("span", `badge ${kind}`, label);
}

function stat(label, value) {
  const node = el("div", "workspace-stat");
  node.append(el("strong", "", String(value)), el("span", "", label));
  return node;
}

function section(title) {
  const node = el("section", "detail-section");
  node.append(el("h4", "detail-label", title));
  return node;
}

function list(items, format = value => String(value)) {
  const node = el("ul", "gap-list");
  for (const item of items) node.append(el("li", "", format(item)));
  return node;
}

function renderModels() {
  const box = $("team");
  box.replaceChildren();
  for (const [role, model] of Object.entries(state.models)) {
    const card = el("article", "team-card");
    card.append(el("span", `role-icon ${role}`, role === "worker" ? "K" : role === "manager" ? "◇" : "✓"));
    const copy = el("div", "role-copy");
    const title = el("div", "role-title", model.name);
    title.append(el("span", "role-tag", role));
    copy.append(title, el("div", "role-model", model.route), el("div", "role-provider", `${model.effort} effort`));
    card.append(copy);
    box.append(card);
  }
}

function renderList() {
  const query = $("search").value.toLowerCase();
  const filter = $("filter").value;
  const rows = state.engagements.filter(row =>
    (filter === "all" || row.status === filter)
      && `${row.id} ${row.target}`.toLowerCase().includes(query)
  );
  $("engagement-count").textContent = rows.length;
  const box = $("engagement-list");
  box.replaceChildren();
  if (!rows.length) {
    const empty = el("div", "empty-list");
    empty.append(
      el("span", "empty-symbol", "◇"),
      el("h3", "", "No matching engagements"),
      el("code", "", "grypton init --target HOST"),
    );
    box.append(empty);
    return;
  }
  for (const row of rows) {
    const button = el("button", `case-item${selected === row.id ? " selected" : ""}`);
    button.type = "button";
    const top = el("div", "case-topline");
    top.append(el("span", "case-id", `ENG / ${row.id.toUpperCase()}`), badge(row.status));
    button.append(top, el("div", "case-title", row.target));
    const meta = el("div", "case-meta");
    meta.append(
      el("span", "", `${row.turns} turns`),
      el("span", "", `${row.tool_calls} tools`),
      el("span", "", `${row.finding_families} ${row.finding_families === 1 ? "family" : "families"}`),
      el("span", "", `${row.finding_cases} cases`),
      el("span", "", `${row.confirmed} confirmed cases`),
    );
    button.append(meta);
    button.onclick = () => {
      selected = row.id;
      renderList();
      loadDetail();
    };
    box.append(button);
  }
}

function keyValue(title, rows) {
  const wrapper = section(title);
  const grid = el("div", "kv-grid");
  for (const [key, value] of rows) {
    const row = el("div", "kv-row");
    row.append(el("span", "kv-key", key), el("span", "kv-value", String(value)));
    grid.append(row);
  }
  wrapper.append(grid);
  return wrapper;
}

function astraState(findingCase) {
  if (findingCase.astra && findingCase.astra.verdict) return findingCase.astra.verdict;
  if (findingCase.status === "validation-pending") return "pending";
  if (/^P[12]$/i.test(String(findingCase.severity || ""))
      && findingCase.status !== "suppressed-by-scope") return "pending";
  return "not-requested";
}

function renderFindingFamilies(detail) {
  if (!detail.finding_family_rows.length && !detail.finding_family_integrity_errors.length) return null;
  const wrapper = section("FINDING FAMILIES / EVIDENCE CASES / ASTRA");

  if (detail.finding_family_integrity_errors.length) {
    const warning = el(
      "p",
      "family-warning",
      `Family catalog integrity has ${detail.finding_family_integrity_errors.length} error(s). Cases are shown as safe singletons.`,
    );
    wrapper.append(warning);
  }

  for (const family of detail.finding_family_rows) {
    const card = el("article", "finding-family-card");
    const top = el("div", "finding-family-top");
    top.append(
      el("span", "finding-family-id", `FAMILY ${family.family_id}`),
      el("span", "finding-family-count", `${family.case_count} ${family.case_count === 1 ? "case" : "cases"}`),
    );
    card.append(top);

    const root = family.root_cause
      || family.cases[0]?.vuln_class
      || family.cases[0]?.title
      || "Standalone evidence case";
    card.append(el("h5", "", root));
    const familyMeta = [];
    if (family.virtual) familyMeta.push("singleton");
    if (family.separate_reason) familyMeta.push(`separate: ${family.separate_reason}`);
    if (familyMeta.length) card.append(el("p", "finding-family-meta", familyMeta.join(" · ")));

    const cases = el("div", "finding-cases");
    for (const findingCase of family.cases) {
      const row = el("article", "finding-case-row");
      const caseTop = el("div", "finding-case-top");
      caseTop.append(el("span", "finding-id", findingCase.id), badge(findingCase.status || "reported"));
      const verdict = astraState(findingCase);
      caseTop.append(badge(`Astra: ${verdict}`));
      row.append(caseTop);
      const severity = findingCase.astra?.severity || findingCase.severity || "?";
      row.append(el("h6", "", `${severity} · ${findingCase.title || "Untitled case"}`));
      const caseMeta = [findingCase.case_kind, findingCase.vuln_class, findingCase.surface].filter(Boolean);
      if (caseMeta.length) row.append(el("p", "finding-meta", caseMeta.join(" · ")));
      cases.append(row);
    }
    if (family.cases_omitted) {
      cases.append(el("p", "finding-omission", `${family.cases_omitted} earlier case(s) omitted`));
    }
    card.append(cases);
    wrapper.append(card);
  }

  const omitted = [];
  if (detail.finding_family_rows_omitted) omitted.push(`${detail.finding_family_rows_omitted} earlier families`);
  if (detail.finding_case_rows_omitted) omitted.push(`${detail.finding_case_rows_omitted} earlier cases`);
  if (omitted.length) wrapper.append(el("p", "finding-omission", `${omitted.join(" and ")} omitted from this bounded view.`));
  return wrapper;
}

function renderDetail(detail) {
  const box = $("detail");
  box.replaceChildren();
  const heading = el("div", "detail-heading");
  heading.append(el("span", "detail-eyebrow", `ENGAGEMENT / ${detail.id.toUpperCase()}`), badge(detail.status));
  box.append(heading, el("h3", "detail-title", detail.target));

  const stats = el("div", "workspace-stats");
  stats.append(
    stat("turns", detail.turns),
    stat("tool calls", detail.tool_calls),
    stat("flows", detail.flows),
    stat("families / cases", `${detail.finding_families} / ${detail.finding_cases}`),
    stat("confirmed cases", detail.confirmed),
  );
  box.append(stats);

  box.append(keyValue("PINNED ROUTE ACTIVITY", [
    ["Kraude calls", detail.provider_calls.worker],
    ["Kryptex calls", detail.provider_calls.manager],
    ["Astra calls", detail.provider_calls.validator],
    ["workspace", detail.workspace],
  ]));

  const scope = section("BINDING SCOPE");
  scope.append(list([
    `in: ${detail.scope.in_scope.join(", ") || "—"}`,
    `out: ${detail.scope.out_of_scope.join(", ") || "—"}`,
    ...detail.scope.hard_rules,
  ]));
  box.append(scope);

  if (detail.tool_rows.length) {
    const tools = section("RECENT TOOL ACTIVITY");
    tools.append(list(detail.tool_rows.slice(-20).reverse(), row => `${row.ok ? "✓" : "!"} ${row.tool} · ${row.summary}`));
    box.append(tools);
  }
  if (detail.flow_rows.length) {
    const flows = section("BURP-LIKE CAPTURES");
    flows.append(list(detail.flow_rows.slice(0, 20), row => `${row.id} · ${row.bytes} bytes`));
    box.append(flows);
  }

  const findings = renderFindingFamilies(detail);
  if (findings) box.append(findings);

  if (detail.surface_rows.length) {
    const surface = section("RECENT ATTACK SURFACE");
    surface.append(list(detail.surface_rows.slice(-20).reverse(), row => `${row.kind || "item"} · ${row.item}`));
    box.append(surface);
  }
  if (detail.tested_rows.length) {
    const tested = section("RECENT TESTED TECHNIQUES");
    tested.append(list(detail.tested_rows.slice(-20).reverse(), row => `${row.surface} · ${row.technique} → ${row.result}`));
    box.append(tested);
  }
  if (detail.last_directive) {
    box.append(keyValue("NEXT KRYPTEX DIRECTIVE", [["directive", detail.last_directive]]));
  }
}

async function loadDetail() {
  if (!selected) return;
  try {
    renderDetail(await get(`/api/engagements/${encodeURIComponent(selected)}`));
  } catch (error) {
    $("detail").replaceChildren(el("p", "detail-text", error.message));
  }
}

async function refresh() {
  if (busy) return;
  busy = true;
  $("refresh").disabled = true;
  try {
    state = await get("/api/state");
    for (const key of ["engagements", "running", "tools"]) {
      $(`count-${key}`).textContent = state.counts[key];
    }
    $("count-findings").textContent = `${state.counts.finding_families}F / ${state.counts.finding_cases}C`;
    $("count-findings-caption").textContent = `${state.counts.confirmed} confirmed evidence cases`;
    $("nav-count").textContent = state.counts.engagements;
    renderModels();
    if (!selected && state.engagements.length) selected = state.engagements[0].id;
    if (selected && !state.engagements.some(row => row.id === selected)) selected = null;
    renderList();
    if (selected) await loadDetail();
    $("connection-label").textContent = "Connected";
    $("connection-dot").classList.remove("offline");
    $("error-banner").hidden = true;
    $("updated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    $("error-banner").textContent = error.message;
    $("error-banner").hidden = false;
    $("connection-label").textContent = "Disconnected";
    $("connection-dot").classList.add("offline");
  } finally {
    busy = false;
    $("refresh").disabled = false;
  }
}

$("search").oninput = renderList;
$("filter").onchange = renderList;
$("refresh").onclick = refresh;

function tick() {
  $("clock").textContent = new Date().toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
}

tick();
refresh();
setInterval(tick, 30000);
setInterval(() => {
  if (!document.hidden) refresh();
}, 5000);
