'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const http = require('node:http');
const path = require('node:path');

const PORT = 13999;
let server;

before(async () => {
  server = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: { ...process.env, PORT: String(PORT) },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('server boot timeout')), 5000);
    server.stdout.on('data', (data) => {
      if (data.toString().includes(`http://localhost:${PORT}`)) {
        clearTimeout(timer);
        resolve();
      }
    });
    server.on('exit', (code) => reject(new Error(`server exited early: code=${code}`)));
  });
});

after(() => {
  if (server && !server.killed) server.kill();
});

function request(reqPath, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port: PORT,
      path: reqPath,
      method: options.method || 'GET',
      headers: options.headers || {}
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks)
        });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

test('GET / serves index.html', async () => {
  const res = await request('/');
  assert.equal(res.status, 200);
  assert.match(res.headers['content-type'], /text\/html/);
  assert.match(res.body.toString(), /Edge Demo Playground/);
});

test('GET /api/time returns 200 with JSON', async () => {
  const res = await request('/api/time');
  assert.equal(res.status, 200);
  assert.match(res.headers['content-type'], /application\/json/);
  const json = JSON.parse(res.body);
  assert.ok(json.now, 'expected `now` field');
});

test('GET /api/origin returns hostname and node info', async () => {
  const res = await request('/api/origin');
  assert.equal(res.status, 200);
  const json = JSON.parse(res.body);
  assert.ok(json.hostname);
  assert.ok(json.nodeVersion);
  assert.equal(typeof json.uptimeSeconds, 'number');
});

test('/api/cache/short emits max-age=10', async () => {
  const res = await request('/api/cache/short');
  assert.equal(res.status, 200);
  assert.match(res.headers['cache-control'], /max-age=10/);
});

test('/api/cache/private emits no-store', async () => {
  const res = await request('/api/cache/private');
  assert.equal(res.status, 200);
  assert.match(res.headers['cache-control'], /no-store/);
});

test('/api/cache/surrogate sends both Surrogate-Control and no-store', async () => {
  const res = await request('/api/cache/surrogate');
  assert.equal(res.status, 200);
  assert.match(res.headers['cache-control'], /no-store/);
  assert.match(res.headers['surrogate-control'], /max-age=300/);
});

test('/api/cache/etag returns 304 on If-None-Match match', async () => {
  const first = await request('/api/cache/etag');
  assert.equal(first.status, 200);
  const etag = first.headers.etag;
  assert.ok(etag, 'expected ETag header');
  const second = await request('/api/cache/etag', { headers: { 'If-None-Match': etag } });
  assert.equal(second.status, 304);
  assert.equal(second.body.length, 0);
});

test('/api/inspect-response with x-demo-status: 304 returns 304, no body, no Content-Length', async () => {
  const res = await request('/api/inspect-response', { headers: { 'x-demo-status': '304' } });
  assert.equal(res.status, 304);
  assert.equal(res.body.length, 0);
  // RFC 9110: 304 must not include Content-Length. Was the original hang bug.
  assert.equal(res.headers['content-length'], undefined);
});

test('/api/inspect-response with x-demo-status: 204 returns 204 bodyless', async () => {
  const res = await request('/api/inspect-response', { headers: { 'x-demo-status': '204' } });
  assert.equal(res.status, 204);
  assert.equal(res.body.length, 0);
  assert.equal(res.headers['content-length'], undefined);
});

test('/api/inspect-response with x-demo-status: 200 echoes status in body + custom header', async () => {
  const res = await request('/api/inspect-response', { headers: { 'x-demo-status': '200' } });
  assert.equal(res.status, 200);
  const json = JSON.parse(res.body);
  assert.equal(json.statusCodeApplied, 200);
  assert.equal(res.headers['x-demo-applied-status'], '200');
});

test('/api/lfo?bytes=1024 returns exactly 1024 bytes with Accept-Ranges', async () => {
  const res = await request('/api/lfo?bytes=1024');
  assert.equal(res.status, 200);
  assert.equal(res.body.length, 1024);
  assert.equal(res.headers['content-length'], '1024');
  assert.equal(res.headers['accept-ranges'], 'bytes');
  assert.ok(res.headers.etag);
  assert.equal(res.headers['x-lfo-total-size'], '1024');
});

test('/api/lfo HEAD returns headers but zero body', async () => {
  const res = await request('/api/lfo?bytes=1048576', { method: 'HEAD' });
  assert.equal(res.status, 200);
  assert.equal(res.headers['content-length'], '1048576');
  assert.equal(res.body.length, 0);
});

test('/api/lfo Range bytes=0-99 returns 206 with 100 bytes and Content-Range', async () => {
  const res = await request('/api/lfo?bytes=10000', { headers: { Range: 'bytes=0-99' } });
  assert.equal(res.status, 206);
  assert.equal(res.body.length, 100);
  assert.equal(res.headers['content-range'], 'bytes 0-99/10000');
});

test('/api/lfo Range with start past end returns 416', async () => {
  const res = await request('/api/lfo?bytes=1000', { headers: { Range: 'bytes=99999-' } });
  assert.equal(res.status, 416);
  assert.match(res.headers['content-range'], /bytes \*\/1000/);
});

test('/api/lfo: two identical Range fetches return byte-identical content', async () => {
  const a = await request('/api/lfo?bytes=10485760', { headers: { Range: 'bytes=1000-1999' } });
  const b = await request('/api/lfo?bytes=10485760', { headers: { Range: 'bytes=1000-1999' } });
  assert.equal(a.status, 206);
  assert.equal(b.status, 206);
  assert.ok(a.body.equals(b.body), 'expected byte-identical ranges across two fetches');
});

test('/api/lfo clamps bytes above 2 GB cap', async () => {
  const huge = 5 * 1024 * 1024 * 1024; // 5 GB requested
  const res = await request(`/api/lfo?bytes=${huge}`, { method: 'HEAD' });
  assert.equal(res.status, 200);
  assert.equal(res.headers['content-length'], String(2 * 1024 * 1024 * 1024));
});

test('/api/log returns the request log structure', async () => {
  const res = await request('/api/log');
  assert.equal(res.status, 200);
  const json = JSON.parse(res.body);
  assert.equal(typeof json.total, 'number');
  assert.ok(Array.isArray(json.requests));
  // Pick any entry to verify field shape — order isn't guaranteed across
  // concurrent test cases.
  const anyEntry = json.requests.find((r) => r.path);
  assert.ok(anyEntry, 'expected at least one log entry');
  assert.ok('grn' in anyEntry, 'expected grn field on log entry');
  assert.ok('clientIp' in anyEntry);
  assert.ok('edgeIp' in anyEntry);
  assert.ok('tcpPeer' in anyEntry);
});

test('/api/log captures grn from request header (regardless of header name)', async () => {
  await request('/api/time', { headers: { grn: '0.test.123.abc' } });
  const res = await request('/api/log');
  const log = JSON.parse(res.body);
  const apiTime = log.requests.find((r) => r.path === '/api/time' && r.grn === '0.test.123.abc');
  assert.ok(apiTime, 'expected /api/time entry with captured grn');
});

test('/api/cors with no params returns no Access-Control-* headers', async () => {
  const res = await request('/api/cors');
  assert.equal(res.status, 200);
  assert.equal(res.headers['access-control-allow-origin'], undefined);
  assert.equal(res.headers['access-control-allow-credentials'], undefined);
});

test('/api/cors echoes configured Access-Control-Allow-Origin', async () => {
  const res = await request('/api/cors?allow_origin=https://example.com');
  assert.equal(res.headers['access-control-allow-origin'], 'https://example.com');
});

test('/api/cors with allow_credentials=true sets the header', async () => {
  const res = await request('/api/cors?allow_origin=*&allow_credentials=true');
  assert.equal(res.headers['access-control-allow-origin'], '*');
  assert.equal(res.headers['access-control-allow-credentials'], 'true');
});

test('/api/cors OPTIONS preflight returns 204 with allow_methods + allow_headers + max_age', async () => {
  const res = await request('/api/cors?allow_origin=*&allow_methods=GET,POST,DELETE&allow_headers=content-type,x-custom&max_age=3600', { method: 'OPTIONS' });
  assert.equal(res.status, 204);
  assert.equal(res.body.length, 0);
  assert.equal(res.headers['access-control-allow-methods'], 'GET,POST,DELETE');
  assert.equal(res.headers['access-control-allow-headers'], 'content-type,x-custom');
  assert.equal(res.headers['access-control-max-age'], '3600');
});

test('/api/cors vary_origin=true emits Vary: Origin', async () => {
  const res = await request('/api/cors?allow_origin=https://x.com&vary_origin=true');
  assert.match(res.headers['vary'] || '', /Origin/);
});

test('GET /akamai/sureroute-test-object.html serves the SureRoute probe target', async () => {
  const res = await request('/akamai/sureroute-test-object.html');
  assert.equal(res.status, 200);
  assert.match(res.headers['content-type'], /text\/html/);
  // SureRoute probes prefer an object large enough to give meaningful timing.
  assert.ok(res.body.length >= 8192, `expected >=8 KB, got ${res.body.length} bytes`);
});

test('Unknown route returns 404 JSON with availableRoutes', async () => {
  const res = await request('/api/nope');
  assert.equal(res.status, 404);
  const json = JSON.parse(res.body);
  assert.ok(Array.isArray(json.availableRoutes));
  assert.ok(json.availableRoutes.length > 5);
});
