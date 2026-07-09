const http = require('http');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const path = require('path');
const { URL } = require('url');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

const FACTS = [
  'Akamai EdgeScape headers carry country, region, city, and ASN data — perfect for geo-based config.',
  'A 304 Not Modified is the cheapest possible response — bytes saved everywhere.',
  'You can override response status with the x-demo-status request header.'
];

const JOKES = [
  { setup: 'Why do developers love dark mode?', punchline: 'Because light attracts bugs.' },
  { setup: 'Why did the server go to therapy?', punchline: 'It had too many unresolved requests.' },
  { setup: 'Why did the CDN blush?', punchline: 'It got cached looking at origin.' }
];

// LFO (Large File Object) - pre-generate a 1 MB chunk of random bytes once
// at boot, then tile it across responses up to 2 GB. Random bytes keep the
// payload incompressible so transfer-size measurements reflect real bandwidth
// rather than gzip/brotli compression at the edge.
const LFO_CHUNK_SIZE = 1024 * 1024;             // 1 MB
const LFO_CHUNK = crypto.randomBytes(LFO_CHUNK_SIZE);
const LFO_MAX_BYTES = 2 * 1024 * 1024 * 1024;   // 2 GB cap
const LFO_ETAG = `"lfo-${crypto.createHash('sha1').update(LFO_CHUNK).digest('hex').slice(0, 16)}"`;

// Stable ETag value for the conditional-GET demo. Recomputed when server boots.
const STARTUP_TIME = new Date();
const ETAG_VALUE = `"${crypto.createHash('sha1').update(STARTUP_TIME.toISOString()).digest('hex').slice(0, 16)}"`;

// --- Failover simulator: in-memory, no persistence, no timers.
// Expiry is evaluated lazily on every read; restart resets to healthy.
// Failures gate ONLY /api/failover/test and /api/cache/sie so the control
// API, /api/log, and all pages stay reachable while "broken".
const FAILOVER_MODES = ['connection-reset', 'timeout'];
const FAILOVER_MAX_SECONDS = 300;
const FAILOVER_DEFAULT_SECONDS = 60;
// Hold a timeout-mode request silent past Akamai's default 120s read timeout
// so the edge actually declares an Origin Timeout, then free the socket.
const FAILOVER_TIMEOUT_HOLD_MS = 125000;
let failover = { mode: 'off', expiresAt: 0 };

// --- Auth: realistic sign-up / login / password-change endpoints as an
// edge & WAF test target (throw SQLi/XSS at them, exercise Set-Cookie handling
// at the edge, cache-bypass on authed routes). In-memory only, node:crypto
// scrypt hashing, restart wipes all accounts and sessions. NOT real auth.
const users = new Map();      // username -> { salt, hash, createdAt }
const sessions = new Map();   // token -> { username, createdAt }
const SESSION_MAX_AGE = 3600; // seconds

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function makeUser(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt, hash: hashPassword(password, salt), createdAt: new Date().toISOString() };
}
function passwordMatches(user, password) {
  const candidate = Buffer.from(hashPassword(password, user.salt), 'hex');
  const stored = Buffer.from(user.hash, 'hex');
  return candidate.length === stored.length && crypto.timingSafeEqual(candidate, stored);
}
function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > -1) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
function sessionUser(req) {
  const token = parseCookies(req).session;
  if (!token) return null;
  const s = sessions.get(token);
  return s ? s.username : null;
}
// username: 3-32 chars, letters/digits/_.- ; password: 8-128 chars.
function validCredentials(username, password) {
  if (typeof username !== 'string' || !/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
    return 'username must be 3-32 chars: letters, digits, _ . -';
  }
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
    return 'password must be 8-128 characters';
  }
  return null;
}

// Live request log
const requestLog = [];
let totalRequests = 0;
let nextRequestId = 1;

// Strip the IPv4-mapped-IPv6 prefix so 127.0.0.1 doesn't show as ::ffff:127.0.0.1
function normalizeIp(ip) {
  if (!ip) return null;
  if (ip.startsWith('::ffff:')) return ip.slice(7);
  return ip;
}

// "Edge IP" = the IP that connected to *the front door of this stack*.
// When Node is behind a local nginx (TLS terminator), the TCP peer is
// 127.0.0.1, but the real edge IP that hit nginx is in X-Real-IP (or the
// rightmost entry of X-Forwarded-For — that's the closest hop). Only trust
// these headers when the TCP peer is local; otherwise the TCP peer is itself
// the edge.
function resolveEdgeIp(req) {
  const peer = normalizeIp(req.socket?.remoteAddress);
  const isLocalProxy = peer === '127.0.0.1' || peer === '::1' || peer === 'localhost';
  if (isLocalProxy) {
    const realIp = req.headers['x-real-ip'];
    if (realIp) return realIp.trim();
    const xff = req.headers['x-forwarded-for'];
    if (xff) {
      const parts = xff.split(',').map((s) => s.trim()).filter(Boolean);
      if (parts.length) return parts[parts.length - 1];
    }
  }
  return peer;
}

function recordRequest(req, res, startedAt) {
  totalRequests += 1;
  const id = nextRequestId++;
  // Copy headers so later mutations on req don't affect the snapshot.
  const headers = { ...req.headers };
  // Akamai (and most reverse proxies) populate True-Client-IP with the real
  // end-user. Edge IP is whatever hit our front-door (nginx → resolved from
  // X-Real-IP, or direct → the TCP peer).
  const clientIp = headers['true-client-ip'] || null;
  const tcpPeer = normalizeIp(req.socket?.remoteAddress);
  const edgeIp = resolveEdgeIp(req);
  requestLog.unshift({
    id,
    at: new Date(startedAt).toISOString(),
    durationMs: Date.now() - startedAt,
    method: req.method,
    path: req.url,
    status: res.statusCode,
    httpVersion: req.httpVersion,
    host: headers.host || null,
    clientIp,
    edgeIp,
    tcpPeer,
    grn: headers['grn']
       || headers['x-akamai-request-id']
       || headers['akamai-request-id']
       || headers['x-akamai-edge-request-id']
       || null,
    xForwardedFor: headers['x-forwarded-for'] || null,
    xRealIp: headers['x-real-ip'] || null,
    ua: (headers['user-agent'] || '').slice(0, 200),
    headers
  });
  if (requestLog.length > 50) requestLog.pop();
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  // Per RFC 9110, 1xx / 204 / 304 responses MUST NOT include a message body.
  // Node's HTTP module silently drops the body for these statuses, so if we
  // also sent Content-Length the client would hang waiting for bytes that
  // never arrive. Send headers only.
  const isBodyless =
    statusCode === 204 ||
    statusCode === 304 ||
    (statusCode >= 100 && statusCode < 200);
  if (isBodyless) {
    res.writeHead(statusCode, { ...extraHeaders });
    res.end();
    return;
  }
  const body = Buffer.from(JSON.stringify(payload, null, 2));
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    ...extraHeaders
  });
  res.end(body);
}

function serveFile(res, filePath) {
  fs.readFile(filePath, (err, data) => {
    if (err) { sendJson(res, 404, { error: 'Not found' }); return; }
    const ext = path.extname(filePath);
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    const headers = { 'Content-Type': contentType };
    if (['.svg', '.png', '.jpg', '.jpeg', '.css', '.js'].includes(ext)) {
      headers['Cache-Control'] = 'public, max-age=300';
    }
    res.writeHead(200, headers);
    res.end(data);
  });
}

function normalizeStatus(code) {
  const parsed = Number.parseInt(code, 10);
  if (Number.isNaN(parsed)) return 200;
  if (parsed < 100 || parsed > 599) return 400;
  return parsed;
}

function pickRandom(items) { return items[Math.floor(Math.random() * items.length)]; }

function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => {
      chunks.push(chunk);
      const size = chunks.reduce((acc, value) => acc + value.length, 0);
      if (size > 1_000_000) reject(new Error('Payload too large'));
    });
    req.on('end', () => {
      if (chunks.length === 0) { resolve({}); return; }
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(new Error('Invalid JSON body')); }
    });
    req.on('error', () => reject(new Error('Request stream error')));
  });
}

function failoverStatus() {
  if (failover.mode !== 'off' && failover.expiresAt <= Date.now()) {
    failover = { mode: 'off', expiresAt: 0 };
  }
  const active = failover.mode !== 'off';
  return {
    active,
    mode: failover.mode,
    remainingSeconds: active ? Math.ceil((failover.expiresAt - Date.now()) / 1000) : 0
  };
}

// Returns true when the failure mode consumed the response.
function applyFailover(req, res) {
  const status = failoverStatus();
  if (!status.active) return false;
  switch (status.mode) {
    case 'connection-reset':
      // statusCode 0 = "no HTTP response existed" in the request log
      res.statusCode = 0;
      res.socket.destroy();
      return true;
    case 'timeout': {
      // Stay completely silent so the edge hits its own read timeout (Akamai
      // default 120s) and declares an Origin Timeout. Free the socket just
      // past that so it doesn't pin forever; clear on early client/edge abort.
      const t = setTimeout(() => {
        if (!res.writableEnded) res.socket.destroy();
      }, FAILOVER_TIMEOUT_HOLD_MS);
      req.on('close', () => clearTimeout(t));
      return true;
    }
    default:
      return false;
  }
}

function parseEdgescape(headerValue) {
  if (!headerValue || typeof headerValue !== 'string') return null;
  const out = {};
  for (const part of headerValue.split(',')) {
    const [k, v] = part.split('=');
    if (k && v !== undefined) out[k.trim().toLowerCase()] = v.trim();
  }
  return out;
}

const server = http.createServer(async (req, res) => {
  const startedAt = Date.now();
  let recorded = false;
  const recordOnce = () => {
    if (recorded) return;
    recorded = true;
    recordRequest(req, res, startedAt);
  };
  res.on('finish', recordOnce);
  res.on('close', recordOnce);

  const requestUrl = new URL(req.url, `http://${req.headers.host || `localhost:${PORT}`}`);
  const pathname = requestUrl.pathname;

  // --- Existing simple endpoints
  if (pathname === '/api/time') {
    sendJson(res, 200, { now: new Date().toISOString(), unix: Date.now() }, { 'Cache-Control': 'no-store' });
    return;
  }

  if (pathname === '/api/popular-locations') {
    sendJson(res, 200, { locations: ['Sydney', 'São Paulo', 'Frankfurt', 'Singapore', 'Johannesburg'] }, { 'Cache-Control': 'public, max-age=600' });
    return;
  }

  if (pathname === '/api/fact') {
    sendJson(res, 200, { fact: pickRandom(FACTS) }, { 'Cache-Control': 'no-store' });
    return;
  }

  if (pathname === '/api/joke') {
    sendJson(res, 200, pickRandom(JOKES), { 'Cache-Control': 'no-store' });
    return;
  }

  // --- Cache-Control demos
  if (pathname === '/api/cache/short') {
    sendJson(res, 200, { ttl: 'short', maxAge: 10, generatedAt: new Date().toISOString() },
      { 'Cache-Control': 'public, max-age=10' });
    return;
  }

  if (pathname === '/api/cache/long') {
    sendJson(res, 200, { ttl: 'long', maxAge: 86400, generatedAt: new Date().toISOString() },
      { 'Cache-Control': 'public, max-age=86400' });
    return;
  }

  if (pathname === '/api/cache/private') {
    sendJson(res, 200, { ttl: 'none', cached: false, generatedAt: new Date().toISOString() },
      { 'Cache-Control': 'private, no-store' });
    return;
  }

  if (pathname === '/api/cache/s-maxage') {
    sendJson(res, 200, {
      note: 'Browser revalidates after 10s; shared caches (the edge) may serve for 120s.',
      generatedAt: new Date().toISOString()
    }, { 'Cache-Control': 'public, max-age=10, s-maxage=120' });
    return;
  }

  if (pathname === '/api/cache/swr') {
    sendJson(res, 200, {
      note: 'After max-age expires the cache may serve this stale for 60s while refetching in the background.',
      generatedAt: new Date().toISOString()
    }, { 'Cache-Control': 'public, max-age=10, stale-while-revalidate=60' });
    return;
  }

  if (pathname === '/api/cache/sie') {
    // Deliberately coupled to the failover simulator: prime the cache, break
    // the origin (POST /api/failover), and the edge can serve this stale for
    // up to 300s instead of surfacing the 500.
    if (applyFailover(req, res)) return;
    sendJson(res, 200, {
      note: 'If the origin errors after max-age expiry, the cache may serve this stale for 300s. Break the origin via /api/failover to demo it.',
      generatedAt: new Date().toISOString()
    }, { 'Cache-Control': 'public, max-age=10, stale-if-error=300' });
    return;
  }

  if (pathname === '/api/cache/etag') {
    const ifNoneMatch = req.headers['if-none-match'];
    const ifModifiedSince = req.headers['if-modified-since'];
    const lastModified = STARTUP_TIME.toUTCString();
    const matchesEtag = ifNoneMatch && ifNoneMatch.split(',').map((s) => s.trim()).includes(ETAG_VALUE);
    const matchesDate = ifModifiedSince && new Date(ifModifiedSince).getTime() >= Math.floor(STARTUP_TIME.getTime() / 1000) * 1000;
    if (matchesEtag || matchesDate) {
      res.writeHead(304, {
        ETag: ETAG_VALUE,
        'Last-Modified': lastModified,
        'Cache-Control': 'public, max-age=60, must-revalidate'
      });
      res.end();
      return;
    }
    sendJson(res, 200, {
      message: 'Fresh response. Re-call with same If-None-Match/If-Modified-Since to receive 304.',
      etag: ETAG_VALUE,
      lastModified
    }, {
      ETag: ETAG_VALUE,
      'Last-Modified': lastModified,
      'Cache-Control': 'public, max-age=60, must-revalidate'
    });
    return;
  }

  if (pathname === '/api/cache/no-cache') {
    // Cacheable, but every use must revalidate. Same conditional logic as
    // /api/cache/etag; only the Cache-Control differs.
    const ifNoneMatch = req.headers['if-none-match'];
    const ifModifiedSince = req.headers['if-modified-since'];
    const lastModified = STARTUP_TIME.toUTCString();
    const matchesEtag = ifNoneMatch && ifNoneMatch.split(',').map((s) => s.trim()).includes(ETAG_VALUE);
    const matchesDate = ifModifiedSince && new Date(ifModifiedSince).getTime() >= Math.floor(STARTUP_TIME.getTime() / 1000) * 1000;
    if (matchesEtag || matchesDate) {
      res.writeHead(304, {
        ETag: ETAG_VALUE,
        'Last-Modified': lastModified,
        'Cache-Control': 'public, no-cache'
      });
      res.end();
      return;
    }
    sendJson(res, 200, {
      note: 'Cacheable but always revalidated: the cache must send If-None-Match every time and gets a cheap 304 back.',
      etag: ETAG_VALUE,
      generatedAt: new Date().toISOString()
    }, {
      ETag: ETAG_VALUE,
      'Last-Modified': lastModified,
      'Cache-Control': 'public, no-cache'
    });
    return;
  }

  // --- Variable-size payload
  if (pathname === '/api/size') {
    const requested = Number.parseInt(requestUrl.searchParams.get('bytes') || '1024', 10);
    const bytes = Math.min(Math.max(Number.isFinite(requested) ? requested : 1024, 1), 5_000_000);
    const filler = Buffer.alloc(bytes, 'A');
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': filler.length,
      'Cache-Control': 'public, max-age=60'
    });
    res.end(filler);
    return;
  }

  // --- Akamai-specific endpoints
  if (pathname === '/api/akamai/client') {
    sendJson(res, 200, {
      'true-client-ip': req.headers['true-client-ip'] || null,
      'x-forwarded-for': req.headers['x-forwarded-for'] || null,
      'akamai-client-ip': req.headers['akamai-client-ip'] || null,
      'remote-address': req.socket.remoteAddress,
      via: req.headers['via'] || null,
      'akamai-origin-hop': req.headers['akamai-origin-hop'] || null
    }, { 'Cache-Control': 'no-store' });
    return;
  }

  if (pathname === '/api/akamai/geo') {
    const raw = req.headers['x-akamai-edgescape'] || req.headers['x-akamai-edge-edgescape'] || null;
    sendJson(res, 200, {
      raw,
      decoded: parseEdgescape(raw),
      hint: raw ? null : 'No X-Akamai-Edgescape header was sent. Enable EdgeScape on the Akamai property to populate this.'
    }, { 'Cache-Control': 'no-store' });
    return;
  }

  if (pathname === '/api/akamai/pragma') {
    const pragma = req.headers['pragma'] || '';
    const directives = pragma.split(',').map((s) => s.trim()).filter(Boolean);
    sendJson(res, 200, {
      receivedPragma: pragma || null,
      directives,
      note: 'When this origin is fronted by Akamai with debug authorization, the edge intercepts these directives and adds X-Cache / X-Cache-Key / X-Check-Cacheable response headers.'
    }, { 'Cache-Control': 'no-store' });
    return;
  }

  // --- Origin info
  if (pathname === '/api/origin') {
    // Fresh Linodes ship with system hostname = "localhost", which makes the
    // homepage tile look broken. Prefer the request Host header (which shows
    // what the user typed / what Akamai forwarded) when the OS hostname is
    // generic, and always expose both fields so callers can pick.
    const osHostname = os.hostname();
    const requestHost = (req.headers.host || '').split(':')[0] || null;
    const isGenericOsHost = !osHostname || osHostname === 'localhost' || osHostname === 'localhost.localdomain';
    const displayHostname = isGenericOsHost && requestHost ? requestHost : osHostname;
    sendJson(res, 200, {
      hostname: displayHostname,
      osHostname,
      requestHost,
      platform: os.platform(),
      arch: os.arch(),
      nodeVersion: process.version,
      pid: process.pid,
      uptimeSeconds: Math.floor(process.uptime()),
      startedAt: new Date(Date.now() - process.uptime() * 1000).toISOString(),
      totalRequests,
      memoryRssMB: Math.round(process.memoryUsage().rss / 1024 / 1024)
    }, { 'Cache-Control': 'no-store' });
    return;
  }

  // --- Slow / artificial latency
  if (pathname === '/api/slow') {
    const requested = Number.parseInt(requestUrl.searchParams.get('ms') || '1000', 10);
    const ms = Math.min(Math.max(Number.isFinite(requested) ? requested : 1000, 0), 30000);
    const t0 = Date.now();
    const timer = setTimeout(() => {
      sendJson(res, 200, {
        delayedMs: ms,
        actualMs: Date.now() - t0,
        completedAt: new Date().toISOString()
      }, { 'Cache-Control': 'no-store' });
    }, ms);
    req.on('close', () => clearTimeout(timer));
    return;
  }

  // --- Failover simulator
  if (pathname === '/api/failover' && req.method === 'GET') {
    sendJson(res, 200, {
      ...failoverStatus(),
      victim: '/api/failover/test',
      modes: FAILOVER_MODES,
      note: 'POST {"mode":"http-500","seconds":60} to break the victim endpoint; {"mode":"off"} to restore. State is in-memory; a server restart heals it.'
    }, { 'Cache-Control': 'no-store' });
    return;
  }

  if (pathname === '/api/failover' && req.method === 'POST') {
    try {
      const body = await parseJsonBody(req);
      const mode = typeof body.mode === 'string' ? body.mode : '';
      if (mode === 'off') {
        failover = { mode: 'off', expiresAt: 0 };
        sendJson(res, 200, { ...failoverStatus(), victim: '/api/failover/test' }, { 'Cache-Control': 'no-store' });
        return;
      }
      if (!FAILOVER_MODES.includes(mode)) {
        sendJson(res, 400, { error: `Unknown mode "${mode}"`, validModes: [...FAILOVER_MODES, 'off'] });
        return;
      }
      const requested = Number.parseInt(body.seconds, 10);
      const seconds = Math.min(Math.max(Number.isFinite(requested) ? requested : FAILOVER_DEFAULT_SECONDS, 1), FAILOVER_MAX_SECONDS);
      failover = { mode, expiresAt: Date.now() + seconds * 1000 };
      sendJson(res, 200, { ...failoverStatus(), victim: '/api/failover/test' }, { 'Cache-Control': 'no-store' });
    } catch (error) {
      sendJson(res, 400, { error: error.message });
    }
    return;
  }

  if (pathname === '/api/failover/test') {
    if (applyFailover(req, res)) return;
    sendJson(res, 200, {
      status: 'ok',
      endpoint: 'failover-victim',
      generatedAt: new Date().toISOString()
    }, { 'Cache-Control': 'no-store' });
    return;
  }

  // --- Redirect demo
  if (pathname === '/api/redirect') {
    const to = requestUrl.searchParams.get('to') || '/';
    const codeRaw = Number.parseInt(requestUrl.searchParams.get('code') || '302', 10);
    const code = Number.isFinite(codeRaw) && codeRaw >= 300 && codeRaw <= 399 ? codeRaw : 302;
    res.writeHead(code, { Location: to, 'Cache-Control': 'no-store' });
    res.end();
    return;
  }

  // --- CORS: fully configurable Access-Control-* response headers. Every
  // CORS-relevant header is driven by query params so you can reproduce
  // (and then mitigate) any cross-origin scenario. Handles OPTIONS preflight
  // identically — the preflight reads the same params.
  if (pathname === '/api/cors') {
    const p = requestUrl.searchParams;
    const allowOrigin     = p.get('allow_origin');         // '*' | explicit origin | 'null' | absent
    const allowMethods    = p.get('allow_methods');        // 'GET,POST,DELETE'
    const allowHeaders    = p.get('allow_headers');        // 'content-type,authorization'
    const allowCreds      = p.get('allow_credentials') === 'true';
    const exposeHeaders   = p.get('expose_headers');       // 'x-custom-foo,etag'
    const maxAge          = p.get('max_age');              // '3600'
    const varyOrigin      = p.get('vary_origin') === 'true';
    const status          = Math.max(100, Math.min(599, Number(p.get('status')) || 200));

    const headers = { 'Cache-Control': 'no-store' };
    if (allowOrigin)         headers['Access-Control-Allow-Origin']      = allowOrigin;
    if (allowMethods)        headers['Access-Control-Allow-Methods']     = allowMethods;
    if (allowHeaders)        headers['Access-Control-Allow-Headers']     = allowHeaders;
    if (allowCreds)          headers['Access-Control-Allow-Credentials'] = 'true';
    if (exposeHeaders)       headers['Access-Control-Expose-Headers']    = exposeHeaders;
    if (maxAge)              headers['Access-Control-Max-Age']           = maxAge;
    if (varyOrigin)          headers['Vary']                             = 'Origin';

    if (req.method === 'OPTIONS') {
      // Preflight: 204 with no body is the conventional response
      res.writeHead(204, headers);
      res.end();
      return;
    }

    sendJson(res, status, {
      message: 'CORS test endpoint',
      observed: {
        method: req.method,
        origin: req.headers.origin || null,
        accessControlRequestMethod: req.headers['access-control-request-method'] || null,
        accessControlRequestHeaders: req.headers['access-control-request-headers'] || null
      },
      configured: { allowOrigin, allowMethods, allowHeaders, allowCreds, exposeHeaders, maxAge, varyOrigin, status }
    }, headers);
    return;
  }

  // --- LFO: Large File Object (up to 2 GB), with Range request support.
  // Useful for testing edge offload, partial-content handling, and how the
  // CDN slices large objects via internal Range GETs to origin.
  if (pathname === '/api/lfo') {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      sendJson(res, 405, { error: 'Method not allowed' });
      return;
    }

    const requested = Number(requestUrl.searchParams.get('bytes'));
    const totalBytes = Number.isFinite(requested) && requested > 0
      ? Math.min(Math.floor(requested), LFO_MAX_BYTES)
      : 100 * 1024 * 1024; // default 100 MB if no ?bytes=

    // Parse Range header (single-range only — all the CDN cares about)
    let start = 0;
    let end = totalBytes - 1;
    let status = 200;
    const rangeHeader = req.headers.range;
    if (rangeHeader) {
      const m = /^bytes=(\d+)-(\d*)$/.exec(rangeHeader.trim());
      if (!m) {
        res.writeHead(416, {
          'Content-Range': `bytes */${totalBytes}`,
          'Cache-Control': 'no-store'
        });
        res.end();
        return;
      }
      const reqStart = Number(m[1]);
      const reqEnd = m[2] === '' ? totalBytes - 1 : Number(m[2]);
      if (reqStart >= totalBytes || reqStart > reqEnd) {
        res.writeHead(416, {
          'Content-Range': `bytes */${totalBytes}`,
          'Cache-Control': 'no-store'
        });
        res.end();
        return;
      }
      start = reqStart;
      end = Math.min(reqEnd, totalBytes - 1);
      status = 206;
    }

    const sendBytes = end - start + 1;
    const headers = {
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(sendBytes),
      'Accept-Ranges': 'bytes',
      'Cache-Control': 'public, max-age=300',
      'ETag': LFO_ETAG,
      'X-Lfo-Total-Size': String(totalBytes)
    };
    if (status === 206) {
      headers['Content-Range'] = `bytes ${start}-${end}/${totalBytes}`;
    }
    res.writeHead(status, headers);

    if (req.method === 'HEAD') {
      res.end();
      return;
    }

    // Stream the body in 1 MB slices, honoring backpressure. Use the chunk
    // as a tiled pattern so byte at file-position N == LFO_CHUNK[N % size];
    // Range requests therefore return content consistent with full GETs.
    let written = 0;
    let aborted = false;
    req.on('close', () => { aborted = true; });
    const writeMore = () => {
      while (!aborted && written < sendBytes) {
        const filePos = start + written;
        const chunkOffset = filePos % LFO_CHUNK_SIZE;
        const fromChunk = LFO_CHUNK_SIZE - chunkOffset;
        const remaining = sendBytes - written;
        const sliceSize = Math.min(fromChunk, remaining);
        const buf = LFO_CHUNK.subarray(chunkOffset, chunkOffset + sliceSize);
        const drained = res.write(buf);
        written += sliceSize;
        if (!drained) {
          res.once('drain', writeMore);
          return;
        }
      }
      if (!aborted) res.end();
    };
    writeMore();
    return;
  }

  // --- Cookies: GET reads, POST sets
  if (pathname === '/api/cookie' && req.method === 'GET') {
    sendJson(res, 200, { cookieHeader: req.headers.cookie || null }, { 'Cache-Control': 'no-store' });
    return;
  }
  if (pathname === '/api/cookie' && req.method === 'POST') {
    try {
      const body = await parseJsonBody(req);
      const name = (typeof body.name === 'string' && body.name.trim()) || 'demo';
      const value = typeof body.value === 'string' ? body.value : 'hello';
      const maxAgeRaw = Number.parseInt(body.maxAge, 10);
      const maxAge = Number.isFinite(maxAgeRaw) && maxAgeRaw >= 0 ? maxAgeRaw : 3600;
      const safeName = name.replace(/[^A-Za-z0-9_\-]/g, '') || 'demo';
      const cookie = `${safeName}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; SameSite=Lax`;
      sendJson(res, 200, { setCookie: cookie }, { 'Set-Cookie': cookie, 'Cache-Control': 'no-store' });
    } catch (error) {
      sendJson(res, 400, { error: error.message });
    }
    return;
  }

  // --- Auth: sign up
  if (pathname === '/api/auth/signup' && req.method === 'POST') {
    try {
      const body = await parseJsonBody(req);
      const username = typeof body.username === 'string' ? body.username.trim() : '';
      const err = validCredentials(username, body.password);
      if (err) { sendJson(res, 400, { error: err }, { 'Cache-Control': 'no-store' }); return; }
      if (users.has(username)) {
        sendJson(res, 409, { error: 'Username already taken' }, { 'Cache-Control': 'no-store' });
        return;
      }
      users.set(username, makeUser(body.password));
      sendJson(res, 201, { message: 'Account created', username }, { 'Cache-Control': 'no-store' });
    } catch (error) {
      sendJson(res, 400, { error: error.message });
    }
    return;
  }

  // --- Auth: log in (sets HttpOnly session cookie)
  if (pathname === '/api/auth/login' && req.method === 'POST') {
    try {
      const body = await parseJsonBody(req);
      const username = typeof body.username === 'string' ? body.username.trim() : '';
      const user = users.get(username);
      // Generic 401 either way — no username enumeration.
      if (!user || typeof body.password !== 'string' || !passwordMatches(user, body.password)) {
        sendJson(res, 401, { error: 'Invalid username or password' }, { 'Cache-Control': 'no-store' });
        return;
      }
      const token = crypto.randomBytes(32).toString('hex');
      sessions.set(token, { username, createdAt: new Date().toISOString() });
      const cookie = `session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${SESSION_MAX_AGE}`;
      sendJson(res, 200, { message: 'Logged in', username }, { 'Set-Cookie': cookie, 'Cache-Control': 'no-store' });
    } catch (error) {
      sendJson(res, 400, { error: error.message });
    }
    return;
  }

  // --- Auth: who am I (reads the session cookie)
  if (pathname === '/api/auth/me' && req.method === 'GET') {
    const username = sessionUser(req);
    if (!username) { sendJson(res, 401, { error: 'Not authenticated' }, { 'Cache-Control': 'no-store' }); return; }
    sendJson(res, 200, { username }, { 'Cache-Control': 'no-store' });
    return;
  }

  // --- Auth: log out (clears the session)
  if (pathname === '/api/auth/logout' && req.method === 'POST') {
    const token = parseCookies(req).session;
    if (token) sessions.delete(token);
    const cookie = 'session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0';
    sendJson(res, 200, { message: 'Logged out' }, { 'Set-Cookie': cookie, 'Cache-Control': 'no-store' });
    return;
  }

  // --- Auth: change password (requires an active session)
  if (pathname === '/api/auth/password' && req.method === 'POST') {
    try {
      const username = sessionUser(req);
      if (!username) { sendJson(res, 401, { error: 'Not authenticated' }, { 'Cache-Control': 'no-store' }); return; }
      const user = users.get(username);
      if (!user) { sendJson(res, 401, { error: 'Not authenticated' }, { 'Cache-Control': 'no-store' }); return; }
      const body = await parseJsonBody(req);
      if (typeof body.currentPassword !== 'string' || !passwordMatches(user, body.currentPassword)) {
        sendJson(res, 403, { error: 'Current password is incorrect' }, { 'Cache-Control': 'no-store' });
        return;
      }
      const err = validCredentials(username, body.newPassword);
      if (err) { sendJson(res, 400, { error: err }, { 'Cache-Control': 'no-store' }); return; }
      users.set(username, { ...makeUser(body.newPassword) });
      // Invalidate all other sessions for this user; keep the current one.
      const keep = parseCookies(req).session;
      for (const [tok, s] of sessions) if (s.username === username && tok !== keep) sessions.delete(tok);
      sendJson(res, 200, { message: 'Password changed' }, { 'Cache-Control': 'no-store' });
    } catch (error) {
      sendJson(res, 400, { error: error.message });
    }
    return;
  }

  // --- Compressible payload
  if (pathname === '/api/compressible') {
    const requested = Number.parseInt(requestUrl.searchParams.get('bytes') || '20480', 10);
    const bytes = Math.min(Math.max(Number.isFinite(requested) ? requested : 20480, 1), 5_000_000);
    const text = 'Akamai edge demo origin. '.repeat(Math.ceil(bytes / 25)).slice(0, bytes);
    res.writeHead(200, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Length': Buffer.byteLength(text),
      'Cache-Control': 'public, max-age=60'
    });
    res.end(text);
    return;
  }

  // --- Server-Sent Events stream
  if (pathname === '/api/stream') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no'
    });
    let i = 0;
    const id = setInterval(() => {
      res.write(`event: tick\n`);
      res.write(`data: ${JSON.stringify({ tick: i, at: new Date().toISOString() })}\n\n`);
      i += 1;
      if (i >= 12) { clearInterval(id); res.end(); }
    }, 500);
    req.on('close', () => clearInterval(id));
    return;
  }

  // --- Live request log
  if (pathname === '/api/log') {
    sendJson(res, 200, {
      total: totalRequests,
      requests: requestLog.slice(0, 25)
    }, { 'Cache-Control': 'no-store' });
    return;
  }

  // --- Header inspection / status forcing
  if (pathname === '/api/inspect-response') {
    const desiredStatus = normalizeStatus(req.headers['x-demo-status']);
    // Echo applied status as a header too — for 204/304/1xx the body is
    // suppressed by HTTP spec, so the client needs another way to read it.
    sendJson(res, desiredStatus, {
      message: 'Header inspection endpoint',
      statusCodeApplied: desiredStatus,
      requestMethod: req.method,
      path: pathname,
      headers: req.headers
    }, {
      'Cache-Control': 'no-store',
      'X-Demo-Applied-Status': String(desiredStatus)
    });
    return;
  }

  // --- Static
  let filePath;
  if (pathname === '/' || pathname === '/index.html') {
    filePath = path.join(PUBLIC_DIR, 'index.html');
  } else {
    filePath = path.join(PUBLIC_DIR, pathname);
  }

  if (!filePath.startsWith(PUBLIC_DIR + path.sep)) { sendJson(res, 403, { error: 'Forbidden' }); return; }

  fs.stat(filePath, (err, stats) => {
    if (!err && stats.isFile()) { serveFile(res, filePath); return; }
    sendJson(res, 404, {
      error: 'Route not found',
      availableRoutes: [
        '/', '/cdn.html', '/responses.html', '/akamai.html', '/cors.html', '/auth.html', '/tools.html',
        '/api/origin', '/api/log',
        'POST /api/auth/signup', 'POST /api/auth/login', 'POST /api/auth/password',
        'GET /api/auth/me', 'POST /api/auth/logout',
        '/api/time', '/api/popular-locations', '/api/fact', '/api/joke',
        '/api/cache/short', '/api/cache/long', '/api/cache/private',
        '/api/cache/etag', '/api/cache/no-cache',
        '/api/cache/s-maxage', '/api/cache/swr', '/api/cache/sie',
        'GET /api/failover', 'POST /api/failover', '/api/failover/test',
        '/api/size?bytes=1024', '/api/compressible?bytes=20480',
        '/api/slow?ms=2000', '/api/redirect?to=/&code=302',
        '/api/lfo?bytes=N', 'GET /api/cookie', 'POST /api/cookie', '/api/stream',
        '/api/cors?allow_origin=...&allow_methods=...&allow_credentials=true',
        '/api/akamai/client', '/api/akamai/geo', '/api/akamai/pragma',
        '/api/inspect-response'
      ]
    });
  });
});

server.listen(PORT, () => {
  console.log(`Demo site running on http://localhost:${PORT}`);
});
