# AkamaiOriginLab

[![Tests](https://github.com/ritbikbharti/AkamaiOriginLab/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/ritbikbharti/AkamaiOriginLab/actions/workflows/test.yml)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](package.json)
[![License](https://img.shields.io/badge/license-GPL%20v3-blue)](LICENSE)

A self-contained origin for testing Akamai (or any CDN) configuration. Modern UI with a dark mode, plus a focused set of endpoints for cache, response-status, CORS, and edge-debug scenarios.

## Pages

- `/` — overview
- `/cdn.html` — **Cache** — Cache-Control TTLs, ETag/304 demo, variable payload sizes, image gallery
- `/responses.html` — **Response Status** — force any HTTP status via `x-demo-status`, inspect the request headers seen by origin
- `/akamai.html` — **Akamai** — True-Client-IP, EdgeScape geo decoding, Pragma debug, Surrogate-Control
- `/cors.html` — **CORS** — fully configurable `Access-Control-*` response headers, request builder, quick scenarios for wildcard / credentials-bug / preflight rejection / exposed headers, sandboxed-iframe runner for real `Origin: null` enforcement
- `/tools.html` — **Misc** — slow responses, redirects, Large File Object (LFO, up to 2 GB — includes 1.5 GB / 1.8 GB / 2 GB presets to bracket Akamai's 1.8 GB LFO threshold) with Range support, cookies, compression, SSE, live request log

## API

### Cache demos
- `GET /api/cache/short` — `Cache-Control: public, max-age=10`
- `GET /api/cache/long` — `Cache-Control: public, max-age=86400`
- `GET /api/cache/private` — `Cache-Control: private, no-store`
- `GET /api/cache/surrogate` — edge caches (`Surrogate-Control: max-age=300`), browser doesn't (`Cache-Control: no-store`)
- `GET /api/cache/etag` — supports `If-None-Match` / `If-Modified-Since`, returns `304` on match

### Akamai-specific
- `GET /api/akamai/client` — echoes `True-Client-IP`, `X-Forwarded-For`, `Via`, etc.
- `GET /api/akamai/geo` — parses `X-Akamai-Edgescape` into a structured object
- `GET /api/akamai/pragma` — echoes incoming `Pragma` debug directives

### Misc
- `GET /api/size?bytes=N` — returns N bytes (max 5,000,000) for transfer benchmarks
- `GET /api/inspect-response` — set `x-demo-status: <code>` to force status
- `GET /api/time`, `GET /api/popular-locations`, `GET /api/fact`, `GET /api/joke`
- `GET /api/cors?allow_origin=*&allow_methods=GET,POST&allow_credentials=true&...` — fully configurable CORS response headers (works for OPTIONS preflight too)

## Run locally

```bash
npm start
```

Open `http://localhost:3000`.

## Tests

```bash
npm test
```

Uses Node's built-in `node:test` runner — no dependencies. Covers cache headers, RFC 9110 bodyless statuses (304/204), LFO with Range/HEAD, request log shape, and GRN capture. CI on every push runs the suite on Node 20 and 22 plus a `bash -n` + ASCII-purity check on the Linode StackScript.

## Deploy

### Node directly
```bash
npm ci --omit=dev
PORT=8080 npm start
```

### Docker
```bash
docker build -t demosite .
docker run -p 3000:3000 demosite
```

### Linode — one-click HTTPS deploy

Public StackScript: **https://cloud.linode.com/stackscripts/2096526**

What it provisions on a fresh Ubuntu Linode:

- Node.js 20 LTS via NodeSource
- Repo cloned to `/opt/AkamaiOriginLab`, runs as an unprivileged `akamai` system user
- nginx reverse proxy on **443** with an auto-generated **self-signed cert** (CN/SAN = the Linode's public IP, or a custom hostname/IP if you provide one)
- Port **80** redirects to **443**
- `ufw` allows only SSH, 80, 443 — the Node port (3000) stays loopback-firewalled
- `systemd` units for both the app and nginx, so it survives reboots

Steps:

1. Open the StackScript page above and click **Deploy New Linode**.
2. Pick a region, plan, root password / SSH key as usual. The only StackScript field is:
   - **Domain or IP for the self-signed cert (CN / SAN)** — leave blank to auto-detect the Linode's public IP, or enter a hostname (e.g. `lab.example.com`) / specific IP for the cert SAN.
3. ~1–2 minutes after first boot, browse to `https://<linode-ip>/`. Your browser will warn about the self-signed cert — click through to proceed.

Logs on the box: `journalctl -u akamai-origin-lab -f` (app), `journalctl -u nginx -f` (proxy), `/var/log/stackscript.log` (provisioning).

The app is stateless except for in-memory feedback history.

#### Replacing the self-signed cert with a real one

SSH in and either:

- Drop a real cert at `/etc/ssl/akamaioriginlab/fullchain.pem` + `privkey.pem` and `sudo systemctl reload nginx`, **or**
- Install certbot and run `sudo certbot --nginx -d your.domain.com` (requires DNS pointing at the Linode).

#### Deploying a fork or modified version

The script source lives at [`deploy/linode-stackscript.sh`](deploy/linode-stackscript.sh). To run your own variant, copy it into a new StackScript in your Linode account (Cloud Manager → StackScripts → Create), edit the hardcoded `REPO_URL` / `BRANCH` at the top to point at your fork, and deploy from that.
