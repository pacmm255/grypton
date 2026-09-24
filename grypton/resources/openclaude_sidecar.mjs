#!/usr/bin/env node
/*
 * Private stdio bridge between Grypton and OpenClaude's supported module API.
 *
 * The gateway token arrives through the inherited environment and is never
 * written to stdout.  Stdout is reserved for bounded JSON protocol messages;
 * provider credentials remain inside OpenClaude's credential loader.
 */
import { readFile, realpath } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import readline from 'node:readline';

const PROTOCOL = 1;
const TOKEN_ENV = 'GRYPTON_OPENCLAUDE_GATEWAY_TOKEN';
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;

function cleanText(value, limit = 2000) {
  let text = String(value ?? '').replace(CONTROL, '');
  text = text.replace(/(bearer\s+)[A-Za-z0-9._~+\/-]+/gi, '$1[REDACTED]');
  text = text.replace(/\bsk-[A-Za-z0-9_-]{12,}\b/g, '[REDACTED]');
  return text.length <= limit ? text : `${text.slice(0, limit)}…`;
}

function cleanNoticeText(value, limit = 1500) {
  // OpenClaude identifies rotated credentials with short fingerprints. They
  // are useful inside its private pool, but add no value to Grypton's durable
  // transcript and can correlate an account across runs.
  let text = String(value ?? '').replace(CONTROL, '');
  text = text.replace(/(bearer\s+)[A-Za-z0-9._~+\/-]+/gi, '$1[REDACTED]');
  text = text.replace(/\bsk-[A-Za-z0-9_-]{12,}\b/g, '[REDACTED]');
  text = text.replace(/\b(key\s+)[a-f0-9]{8}\b/gi, '$1[REDACTED]');
  return text.length <= limit ? text : `${text.slice(0, limit)}…`;
}

function failMessage(error) {
  const message = cleanText(error?.message || error || 'OpenClaude sidecar error', 1000);
  return message || 'OpenClaude sidecar error';
}

function write(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function publicModel(model) {
  const capabilities = model?.capabilities && typeof model.capabilities === 'object'
    ? model.capabilities : {};
  const limits = model?.limits && typeof model.limits === 'object' ? model.limits : {};
  const effort = model?.effort && typeof model.effort === 'object' ? model.effort : {};
  return {
    routeId: cleanText(model?.routeId || model?.id, 300),
    id: cleanText(model?.id, 300),
    provider: cleanText(model?.provider, 160),
    model: cleanText(model?.model, 300),
    label: cleanText(model?.label || model?.routeId || model?.id, 300),
    protocol: cleanText(model?.protocol, 40),
    status: cleanText(model?.status, 40),
    reason: cleanText(model?.reason, 1000),
    aliases: Array.isArray(model?.aliases) ? model.aliases.map(value => cleanText(value, 300)) : [],
    capabilities: {
      tools: capabilities.tools === true,
      reasoning: capabilities.reasoning === true,
      temperature: capabilities.temperature === true,
      input: capabilities.input && typeof capabilities.input === 'object' ? capabilities.input : {},
      output: capabilities.output && typeof capabilities.output === 'object' ? capabilities.output : {},
      reasoningField: typeof capabilities.reasoningField === 'string'
        ? cleanText(capabilities.reasoningField, 80) : null,
    },
    limits: {
      context: Number.isSafeInteger(limits.context) ? limits.context : null,
      input: Number.isSafeInteger(limits.input) ? limits.input : null,
      output: Number.isSafeInteger(limits.output) ? limits.output : null,
    },
    reasoningOptions: Array.isArray(model?.reasoningOptions) ? model.reasoningOptions : [],
    effort: {
      levels: Array.isArray(effort.levels) ? effort.levels.map(value => cleanText(value, 40)) : [],
      aliases: effort.aliases && typeof effort.aliases === 'object' ? effort.aliases : {},
      default: cleanText(effort.default || 'auto', 40),
      parameter: typeof effort.parameter === 'string' ? cleanText(effort.parameter, 80) : null,
      providerDefault: typeof effort.providerDefault === 'string'
        ? cleanText(effort.providerDefault, 40) : null,
    },
    source: cleanText(model?.source, 120),
  };
}

function publicCatalog(catalog) {
  return {
    models: Array.isArray(catalog?.models) ? catalog.models.map(publicModel) : [],
    providers: Array.isArray(catalog?.providers) ? catalog.providers.map(provider => ({
      id: cleanText(provider?.id, 160),
      label: cleanText(provider?.label || provider?.name || provider?.id, 300),
      status: cleanText(provider?.status, 40),
      reason: cleanText(provider?.reason, 1000),
    })) : [],
    warnings: Array.isArray(catalog?.warnings)
      ? catalog.warnings.map(value => cleanText(value, 1000)) : [],
    source: catalog?.source && typeof catalog.source === 'object' ? {
      refreshed: catalog.source.refreshed === true,
      localOnly: catalog.source.localOnly === true,
      discovery: cleanText(catalog.source.discovery, 80),
    } : {},
  };
}

function safeNotice(kind, value = {}) {
  if (kind === 'notice') return {
    type: 'openclaude_notice',
    route: cleanText(value.route, 300),
    message: cleanNoticeText(value.message, 1500),
  };
  if (kind === 'terminal') return {
    type: 'openclaude_terminal',
    route: cleanText(value.route, 300),
    reason: value.reason === 'credential_pool_exhausted'
      ? value.reason : 'provider_terminal',
    upstreamStatus: Number.isSafeInteger(value.upstreamStatus)
      && value.upstreamStatus >= 100 && value.upstreamStatus <= 599
      ? value.upstreamStatus : 0,
    poolSize: Number.isSafeInteger(value.poolSize)
      && value.poolSize > 0 && value.poolSize <= 1000 ? value.poolSize : 0,
    retryAfterSeconds: Number.isSafeInteger(value.retryAfterSeconds)
      && value.retryAfterSeconds > 0 && value.retryAfterSeconds <= 7 * 86400
      ? value.retryAfterSeconds : 0,
  };
  if (kind === 'request') return {
    type: 'openclaude_request',
    route: cleanText(value.route, 300),
    protocol: cleanText(value.protocol, 40),
    tools: Array.isArray(value.tools) ? value.tools.map(item => cleanText(item, 160)).slice(0, 100) : [],
    messages: Number.isSafeInteger(value.messages) ? value.messages : 0,
    stream: value.stream === true,
  };
  return {
    type: 'openclaude_effort',
    route: cleanText(value.route, 300),
    requested: cleanText(value.requested, 40),
    effective: cleanText(value.effective, 40),
    status: cleanText(value.status, 80),
    notices: Array.isArray(value.notices)
      ? value.notices.map(item => cleanText(item, 500)).slice(0, 20) : [],
  };
}

const rootArg = process.argv[2];
const configArg = process.argv[3];
if (!rootArg || !configArg) {
  process.stderr.write('OpenClaude sidecar requires root and config paths.\n');
  process.exit(2);
}

let root;
try { root = await realpath(resolve(rootArg)); }
catch { process.stderr.write('OpenClaude root is unavailable.\n'); process.exit(2); }
const configPath = resolve(configArg);
const token = process.env[TOKEN_ENV];
if (!token || !/^[a-f0-9]{64}$/i.test(token)) {
  process.stderr.write('OpenClaude sidecar gateway token is unavailable.\n');
  process.exit(2);
}

async function moduleFrom(relative) {
  return import(pathToFileURL(join(root, relative)).href);
}

let readConfig, loadCredentialPool, readCatalog, startGateway, packageVersion = '';
try {
  ({ readConfig, loadCredentialPool } = await moduleFrom('src/config.mjs'));
  ({ readCatalog } = await moduleFrom('src/catalog.mjs'));
  ({ startGateway } = await moduleFrom('src/gateway.mjs'));
  const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  packageVersion = cleanText(pkg.version, 80);
} catch (error) {
  process.stderr.write(`Cannot load OpenClaude modules: ${failMessage(error)}\n`);
  process.exit(2);
}

let baseConfig = await readConfig(configPath, process.env);
let catalog = null;
let activeConfig = baseConfig;
let gateway = null;
let selectedRoute = '';
let selectedEffort = '';
let shuttingDown = false;

async function rotateRateLimitedCredential(input, init, observe) {
  const response = await fetch(input, init);
  observe?.(response, init);
  if (response.status !== 429) return response;

  // OpenClaude normally treats an unqualified 429 as a transient provider
  // burst and retries the same key for the configured retry window. Grypton
  // has a credential pool and needs to traverse it once instead. Replace only
  // the private error body with a classification token OpenClaude already
  // recognizes as key-specific exhaustion; preserve the upstream status and
  // retry metadata. Provider error bodies are never exposed or retained.
  try { await response.body?.cancel(); } catch {}
  const headers = new Headers(response.headers);
  headers.set('content-type', 'application/json');
  headers.delete('content-length');
  headers.delete('content-encoding');
  headers.delete('transfer-encoding');
  return new Response(JSON.stringify({ error: { type: 'GoUsageLimit' } }), {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function refreshCatalog(refresh = false) {
  catalog = await readCatalog(baseConfig, {
    env: process.env,
    cwd: process.cwd(),
    refresh: refresh === true,
  });
  activeConfig = catalog.config;
  patchMuseEffort(activeConfig, catalog);
  return publicCatalog(catalog);
}

function emit(kind, value) {
  write({ event: safeNotice(kind, value) });
}

async function start(route, effort, port) {
  if (!catalog) await refreshCatalog(false);
  if (!activeConfig?.routes || !Object.hasOwn(activeConfig.routes, route)) {
    throw new Error(`Unknown OpenClaude route: ${cleanText(route, 300)}`);
  }
  if (gateway) {
    if (route !== selectedRoute || (effort || '') !== selectedEffort) {
      throw new Error('This OpenClaude sidecar already owns a gateway for another route or effort.');
    }
    return { url: gateway.url, headerName: gateway.headerName, route: selectedRoute };
  }
  selectedRoute = route;
  selectedEffort = effort || '';
  let poolSize = 0;
  let credentialPool = [];
  let terminalSent = false;
  // OpenClaude retains its own spent-key cooldowns. Mirror only hashed
  // identities here so pool exhaustion remains observable when a later
  // request starts with one or more keys already benched.
  const credentialFailures = new Map();
  const pruneCredentialFailures = () => {
    const now = Date.now();
    for (const [fingerprint, until] of credentialFailures) {
      if (until <= now) credentialFailures.delete(fingerprint);
    }
  };
  const poolRetryAfterSeconds = () => {
    pruneCredentialFailures();
    if (!credentialPool.length) return 0;
    const deadlines = credentialPool.map(entry => credentialFailures.get(entry?.fingerprint));
    if (deadlines.some(deadline => !(Number.isFinite(deadline) && deadline > Date.now()))) {
      return 0;
    }
    const remaining = Math.ceil((Math.min(...deadlines) - Date.now()) / 1000);
    return Math.max(1, Math.min(7 * 86400, remaining));
  };
  const requestCredential = init => {
    const headers = new Headers(init?.headers || {});
    const bearer = String(headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
    const apiKey = String(headers.get('x-api-key') || '');
    return credentialPool.find(entry => entry?.key === bearer || entry?.key === apiKey);
  };
  const observeCredentialResponse = (response, init) => {
    pruneCredentialFailures();
    const entry = requestCredential(init);
    if (!entry?.fingerprint) return;
    if (response.ok) return;
    if (![401, 402, 429].includes(response.status)) return;
    const retryAfter = Number(response.headers.get('retry-after'));
    const configured = Number(activeConfig?.retry?.keyCooldownMs);
    const fallback = response.status === 429
      ? 60_000
      : Number.isSafeInteger(configured) && configured > 0 ? configured : 900_000;
    const cooldown = Number.isFinite(retryAfter) && retryAfter > 0
      ? Math.round(retryAfter * 1000) : fallback;
    credentialFailures.set(
      entry.fingerprint,
      Date.now() + Math.min(cooldown, 7 * 86_400_000),
    );
    if (!terminalSent && credentialPool.length > 0
        && credentialPool.every(item => credentialFailures.has(item.fingerprint))) {
      terminalSent = true;
      emit('terminal', {
        route: selectedRoute,
        reason: 'credential_pool_exhausted',
        upstreamStatus: response.status,
        poolSize: credentialPool.length,
        retryAfterSeconds: poolRetryAfterSeconds(),
      });
    }
  };
  gateway = await startGateway(activeConfig, {
    token,
    ...(Number.isSafeInteger(port) && port >= 0 && port <= 65535 ? { port } : {}),
    getConfig: () => activeConfig,
    fetch: (input, init) => rotateRateLimitedCredential(
      input, init, observeCredentialResponse,
    ),
    credentialPoolLoader: async provider => {
      const pool = await loadCredentialPool(provider, process.env);
      credentialPool = Array.isArray(pool) ? pool : [];
      poolSize = credentialPool.length;
      pruneCredentialFailures();
      terminalSent = false;
      return credentialPool;
    },
    effortForRoute: routeId => routeId === selectedRoute && selectedEffort && selectedEffort !== 'auto'
      ? selectedEffort : undefined,
    onNotice: value => {
      const message = String(value?.message || '');
      emit('notice', value);
      // This fixed OpenClaude notice is emitted only after a credential-class
      // failure when every key is already benched and the gateway is about to
      // sleep. It also covers classified 403 failures without interpreting or
      // retaining their provider body here.
      const exhausted = message.match(
        /^every key for this provider is spent or limited; waiting (\d+)s\b/i,
      );
      if (!terminalSent && poolSize > 0 && exhausted) {
        const retryAfterSeconds = Number(exhausted[1]);
        terminalSent = true;
        emit('terminal', {
          route: value?.route || selectedRoute,
          reason: 'credential_pool_exhausted',
          upstreamStatus: 0,
          poolSize,
          retryAfterSeconds: Number.isSafeInteger(retryAfterSeconds)
            ? Math.max(1, Math.min(7 * 86400, retryAfterSeconds)) : 0,
        });
      }
    },
    onRequest: value => emit('request', value),
    onEffort: value => emit('effort', value),
  });
  return { url: gateway.url, headerName: gateway.headerName, route: selectedRoute };
}

async function dispatch(method, params = {}) {
  if (method === 'ping') return {
    protocol: PROTOCOL,
    openclaudeVersion: packageVersion,
    gateway: Boolean(gateway),
  };
  if (method === 'catalog') return refreshCatalog(params.refresh === true);
  if (method === 'start') return start(
    cleanText(params.route, 300),
    cleanText(params.effort, 40),
    params.port,
  );
  if (method === 'status') return {
    gateway: Boolean(gateway),
    route: selectedRoute,
    effort: selectedEffort,
    url: gateway?.url || '',
    stats: gateway?.stats || { requests: 0, failures: 0, routes: {} },
  };
  if (method === 'close_gateway') {
    if (gateway) await gateway.close();
    gateway = null;
    return { closed: true };
  }
  if (method === 'shutdown') {
    if (gateway) await gateway.close();
    gateway = null;
    shuttingDown = true;
    return { closed: true };
  }
  throw new Error(`Unknown OpenClaude sidecar method: ${cleanText(method, 80)}`);
}

const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
input.on('line', async line => {
  let request;
  try { request = JSON.parse(line); }
  catch { return write({ id: null, ok: false, error: 'Invalid JSON request.' }); }
  const id = request?.id;
  try {
    const result = await dispatch(request?.method, request?.params);
    write({ id, ok: true, result });
  } catch (error) {
    write({ id, ok: false, error: failMessage(error) });
  }
  if (shuttingDown) {
    input.close();
    setImmediate(() => process.exit(0));
  }
});

async function stop() {
  try { if (gateway) await gateway.close(); } catch {}
  process.exit(0);
}
process.once('SIGTERM', stop);
process.once('SIGINT', stop);
process.stdin.once('end', stop);
function patchMuseEffort(config, discovered) {
  const models = new Map((Array.isArray(discovered?.models) ? discovered.models : [])
    .map(model => [model?.routeId, model]));
  for (const [routeId, route] of Object.entries(config?.routes || {})) {
    if (!/^muse-spark-1\.[23]-contributor$/.test(String(route?.model || '')) || route?.protocol !== 'responses') continue;
    const model = models.get(routeId);
    const levels = [...new Set((Array.isArray(model?.reasoningOptions) ? model.reasoningOptions : [])
      .filter(option => option?.type === 'effort' && Array.isArray(option.values))
      .flatMap(option => option.values)
      .filter(value => ['minimal', 'low', 'medium', 'high', 'xhigh', 'max'].includes(value)))];
    if (!levels.length) continue;
    const profile = {
      version: 1,
      provider: 'opencode-go',
      model: route.model,
      protocol: 'responses',
      levels,
      aliases: {},
      default: 'auto',
      parameter: 'reasoning.effort',
      sources: [],
    };
    route.effort = profile;
    if (model) model.effort = profile;
  }
}
