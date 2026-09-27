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

let readConfig, loadCredentialPool, readCatalog, startGateway;
let OVERFLOW_PATTERN, THINKING_ERROR_PATTERNS;
let packageVersion = '';
try {
  ({ readConfig, loadCredentialPool } = await moduleFrom('src/config.mjs'));
  ({ readCatalog } = await moduleFrom('src/catalog.mjs'));
  ({ startGateway } = await moduleFrom('src/gateway.mjs'));
  ({ OVERFLOW_PATTERN, THINKING_ERROR_PATTERNS } = await moduleFrom('src/anthropic.mjs'));
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

const MAX_CREDENTIAL_POOL = 64;
const MAX_ERROR_CLASSIFICATION_BYTES = 65_536;

function aborted(signal) {
  if (!signal?.aborted) return null;
  return signal.reason instanceof Error
    ? signal.reason
    : new DOMException('The operation was aborted.', 'AbortError');
}

async function boundedErrorResponse(response, signal) {
  const reader = response.body?.getReader();
  if (!reader) return { text: '', response };
  const chunks = [];
  let length = 0;
  try {
    while (length < MAX_ERROR_CLASSIFICATION_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      const part = value.subarray(0, MAX_ERROR_CLASSIFICATION_BYTES - length);
      chunks.push(part);
      length += part.length;
    }
  } catch {} finally {
    try { await reader.cancel(); } catch {}
    try { reader.releaseLock(); } catch {}
  }
  const abortError = aborted(signal);
  if (abortError) throw abortError;
  const body = Buffer.concat(chunks);
  const headers = new Headers(response.headers);
  headers.delete('content-length');
  headers.delete('content-encoding');
  headers.delete('transfer-encoding');
  return {
    text: body.toString('utf8'),
    response: new Response(body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    }),
  };
}

function openClaudeRecoveryKind(status, text) {
  if (![400, 413, 422].includes(status)) return '';
  if (OVERFLOW_PATTERN.test(text)) return 'overflow';
  if (![400, 422].includes(status)) return '';
  const normalized = text.toLowerCase().replaceAll('`', '');
  return /encrypted_content|reasoning item/i.test(text)
    || THINKING_ERROR_PATTERNS.some(
      pattern => pattern.test(text) || pattern.test(normalized),
    )
    ? 'thinking' : '';
}

function canonicalThinkingResponse(response) {
  const headers = new Headers(response.headers);
  headers.set('content-type', 'application/json');
  headers.delete('content-length');
  headers.delete('content-encoding');
  headers.delete('transfer-encoding');
  return new Response(JSON.stringify({
    error: {
      type: 'invalid_request_error',
      message: 'reasoning item encrypted_content was rejected due to an invalid signature in thinking block',
    },
  }), {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function configForExactRoute(config, routeId) {
  const route = config?.routes?.[routeId];
  const provider = route && config?.providers?.[route.provider];
  if (!route || !provider) throw new Error('Selected OpenClaude route is incomplete.');
  const restricted = structuredClone(config);
  restricted.routes = { [routeId]: structuredClone(route) };
  restricted.providers = { [route.provider]: structuredClone(provider) };
  restricted.defaultRoute = routeId;
  restricted.fastRoute = routeId;
  restricted.reasoningRoute = routeId;
  restricted.fallbacks = {};
  delete restricted.aliases;
  delete restricted.council;
  delete restricted.legacyRoutes;
  return restricted;
}

async function refreshCatalog(refresh = false) {
  catalog = await readCatalog(baseConfig, {
    env: process.env,
    cwd: process.cwd(),
    refresh: refresh === true,
  });
  activeConfig = catalog.config;
  patchMuseEffort(activeConfig, catalog);
  patchDeepSeekGoEffort(activeConfig, catalog);
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
  let credentialPool = [];
  const credentialCooldowns = new Map();
  const credentialStatuses = new Map();
  const requestStates = new WeakMap();
  const requestCredential = (init, pool = credentialPool) => {
    const headers = new Headers(init?.headers || {});
    const bearer = String(headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
    const apiKey = String(headers.get('x-api-key') || '');
    return pool.find(entry => entry?.key === bearer || entry?.key === apiKey);
  };
  const initForCredential = (init, key) => {
    const headers = new Headers(init?.headers || {});
    let replaced = false;
    if (/^Bearer\s+/i.test(String(headers.get('authorization') || ''))) {
      headers.set('authorization', `Bearer ${key}`);
      replaced = true;
    }
    if (headers.has('x-api-key')) {
      headers.set('x-api-key', key);
      replaced = true;
    }
    if (!replaced) throw new Error('Provider credential header is unavailable.');
    return { ...init, headers };
  };
  const retryAfterSeconds = response => {
    const retryAfter = Number(response?.headers?.get?.('retry-after'));
    if (Number.isFinite(retryAfter) && retryAfter > 0) {
      return Math.max(1, Math.min(7 * 86400, Math.ceil(retryAfter)));
    }
    const status = Number(response?.status || 0);
    const configured = Number(activeConfig?.retry?.keyCooldownMs);
    const fallbackMs = [401, 402, 403].includes(status)
      ? Number.isSafeInteger(configured) && configured > 0 ? configured : 900_000
      : 60_000;
    return Math.max(1, Math.min(7 * 86400, Math.ceil(fallbackMs / 1000)));
  };
  const pruneCooldowns = () => {
    const now = Date.now();
    for (const [fingerprint, until] of credentialCooldowns) {
      if (until <= now) {
        credentialCooldowns.delete(fingerprint);
        credentialStatuses.delete(fingerprint);
      }
    }
  };
  const poolRetryAfterSeconds = pool => {
    pruneCooldowns();
    if (!pool.length) return 0;
    const deadlines = pool.map(entry => credentialCooldowns.get(entry.fingerprint));
    if (deadlines.some(deadline => !(Number.isFinite(deadline) && deadline > Date.now()))) {
      return 0;
    }
    return Math.max(
      1,
      Math.min(7 * 86400, Math.ceil((Math.min(...deadlines) - Date.now()) / 1000)),
    );
  };
  const bench = (entry, status, seconds) => {
    const bounded = Math.max(1, Math.min(7 * 86400, Number(seconds) || 60));
    credentialCooldowns.set(entry.fingerprint, Date.now() + (bounded * 1000));
    credentialStatuses.set(entry.fingerprint, status);
  };
  const stateFor = init => {
    const signal = init?.signal;
    if (signal && requestStates.has(signal)) return requestStates.get(signal);
    pruneCooldowns();
    const pool = credentialPool.slice();
    const current = requestCredential(init, pool);
    const usable = pool.filter(
      entry => !(credentialCooldowns.get(entry.fingerprint) > Date.now()),
    );
    const ordered = current && usable.some(
      entry => entry.fingerprint === current.fingerprint,
    )
      ? [current, ...usable.filter(entry => entry.fingerprint !== current.fingerprint)]
      : usable;
    const state = {
      signal,
      pool,
      ordered,
      current,
      tried: new Set(),
      terminal: false,
      lastStatus: 0,
      retryAfterSeconds: 0,
      finalRecovery: false,
    };
    if (signal) requestStates.set(signal, state);
    return state;
  };
  const releaseState = state => {
    if (state?.signal) requestStates.delete(state.signal);
  };
  const fetchWithCredentialRotation = async (input, init) => {
    const state = stateFor(init);
    // A provider transport without a pool-backed bearer or API-key header does
    // not expose a safe credential substitution point.
    if (!state.current) {
      releaseState(state);
      return fetch(input, init);
    }
    if (!state.ordered.length) {
      const retry = poolRetryAfterSeconds(state.pool) || 60;
      const statuses = state.pool
        .map(entry => credentialStatuses.get(entry.fingerprint))
        .filter(status => Number.isSafeInteger(status));
      emit('terminal', {
        route: selectedRoute,
        reason: 'credential_pool_exhausted',
        upstreamStatus: statuses.at(-1) || 0,
        poolSize: state.pool.length,
        retryAfterSeconds: retry,
      });
      releaseState(state);
      return new Response(JSON.stringify({
        error: { type: 'GryptonCredentialPoolExhausted' },
      }), {
        status: 400,
        headers: {
          'content-type': 'application/json',
          'retry-after': String(retry),
        },
      });
    }

    let finalResponse = null;
    for (const entry of state.ordered) {
      if (state.tried.has(entry.fingerprint)) continue;
      if (init?.signal?.aborted) {
        releaseState(state);
        throw new DOMException('The operation was aborted.', 'AbortError');
      }
      state.tried.add(entry.fingerprint);
      let response;
      try {
        response = await fetch(
          input,
          entry.fingerprint === state.current.fingerprint
            ? init : initForCredential(init, entry.key),
        );
      } catch (error) {
        if (init?.signal?.aborted || error?.name === 'AbortError') {
          releaseState(state);
          throw error;
        }
        state.lastStatus = 0;
        state.retryAfterSeconds = Math.max(state.retryAfterSeconds, 60);
        bench(entry, 0, 60);
        const hasNext = state.ordered.some(
          candidate => !state.tried.has(candidate.fingerprint),
        );
        if (hasNext) {
          emit('notice', {
            route: selectedRoute,
            message: 'provider connection failed before a response; continuing on key from the configured pool',
          });
          continue;
        }
      }

      if (response?.ok) {
        // Once successful response headers exist, ownership of the body passes
        // to OpenClaude. A later stream failure must never replay the request.
        credentialCooldowns.delete(entry.fingerprint);
        credentialStatuses.delete(entry.fingerprint);
        releaseState(state);
        return response;
      }
      if (response) {
        const retry = retryAfterSeconds(response);
        let bounded;
        try {
          bounded = await boundedErrorResponse(response, init?.signal);
        } catch (error) {
          releaseState(state);
          throw error;
        }
        response = bounded.response;
        const abortError = aborted(init?.signal);
        if (abortError) {
          releaseState(state);
          throw abortError;
        }
        const recovery = openClaudeRecoveryKind(response.status, bounded.text);
        if (recovery === 'thinking') response = canonicalThinkingResponse(response);
        state.lastStatus = response.status;
        state.retryAfterSeconds = Math.max(
          state.retryAfterSeconds,
          retry,
        );
        if (!recovery) bench(entry, response.status, retry);
        finalResponse = response;
        state.finalRecovery = Boolean(recovery);
      }
      const hasNext = state.ordered.some(
        candidate => !state.tried.has(candidate.fingerprint),
      );
      if (hasNext) {
        try { await response?.body?.cancel(); } catch {}
        const abortError = aborted(init?.signal);
        if (abortError) {
          releaseState(state);
          throw abortError;
        }
        finalResponse = null;
        emit('notice', {
          route: selectedRoute,
          message: `provider returned HTTP ${response?.status || 0}; continuing on key from the configured pool`,
        });
        continue;
      }
    }

    const abortError = aborted(init?.signal);
    if (abortError) {
      releaseState(state);
      throw abortError;
    }
    if (finalResponse) {
      if (state.finalRecovery) {
        releaseState(state);
        return finalResponse;
      }
      try { await finalResponse.body?.cancel(); } catch {}
      const abortAfterCancel = aborted(init?.signal);
      if (abortAfterCancel) {
        releaseState(state);
        throw abortAfterCancel;
      }
    }
    if (!state.terminal) {
      state.terminal = true;
      const retry = poolRetryAfterSeconds(state.pool)
        || state.retryAfterSeconds || 60;
      emit('terminal', {
        route: selectedRoute,
        reason: 'credential_pool_exhausted',
        upstreamStatus: state.lastStatus,
        poolSize: state.pool.length,
        retryAfterSeconds: retry,
      });
      state.retryAfterSeconds = retry;
    }
    releaseState(state);
    return new Response(JSON.stringify({
      error: { type: 'GryptonCredentialPoolExhausted' },
    }), {
      status: 400,
      headers: {
        'content-type': 'application/json',
        'retry-after': String(state.retryAfterSeconds || 60),
      },
    });
  };
  const exactConfig = configForExactRoute(activeConfig, selectedRoute);
  gateway = await startGateway(exactConfig, {
    token,
    ...(Number.isSafeInteger(port) && port >= 0 && port <= 65535 ? { port } : {}),
    getConfig: () => configForExactRoute(activeConfig, selectedRoute),
    fetch: fetchWithCredentialRotation,
    credentialPoolLoader: async provider => {
      const pool = await loadCredentialPool(provider, process.env);
      if (!Array.isArray(pool) || !pool.length) {
        throw new Error('No provider credential is available.');
      }
      if (pool.length > MAX_CREDENTIAL_POOL) {
        throw new Error(
          `Provider credential pool exceeds the ${MAX_CREDENTIAL_POOL}-entry limit.`,
        );
      }
      credentialPool = pool.slice();
      return credentialPool;
    },
    effortForRoute: routeId => routeId === selectedRoute && selectedEffort && selectedEffort !== 'auto'
      ? selectedEffort : undefined,
    onNotice: value => emit('notice', value),
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

function patchDeepSeekGoEffort(config, discovered) {
  const routeId = 'go/deepseek-v4.1-flash';
  const route = config?.routes?.[routeId];
  const model = (Array.isArray(discovered?.models) ? discovered.models : [])
    .find(candidate => candidate?.routeId === routeId);
  if (!route || model?.provider !== 'go' || route?.model !== 'deepseek-v4.1-flash'
      || route?.protocol !== 'chat') return;
  if (route?.effort?.parameter) {
    model.effort = route.effort;
    return;
  }
  const levels = [...new Set((Array.isArray(model?.reasoningOptions)
    ? model.reasoningOptions : [])
    .filter(option => option?.type === 'effort' && Array.isArray(option.values))
    .flatMap(option => option.values)
    .filter(value => ['low', 'high', 'max'].includes(value)))];
  if (!levels.length) return;
  const profile = {
    version: 1,
    provider: 'opencode-go',
    model: route.model,
    protocol: 'chat',
    parameter: 'reasoning_effort',
    levels,
    aliases: {},
    default: 'auto',
    providerDefault: 'high',
    sources: ['https://api-docs.deepseek.com/guides/thinking_mode/'],
  };
  route.effort = profile;
  if (model) model.effort = profile;
}
