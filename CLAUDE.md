# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Katarakt** is a multi-layered browser security and anti-fingerprinting platform inspired by Mullvad Browser and Tor Browser. It provides protection at three layers:

1. **Client-side** (Service Worker): Browser-based fingerprint spoofing, tracker blocking, and script analysis
2. **Edge** (Cloudflare Worker): Bot detection, security header injection, and fingerprint protection script delivery
3. **Backend** (Google Cloud Run): WAF rules, DDoS protection, and centralized monitoring

The project implements comprehensive browser fingerprinting countermeasures based on research from the Tor Project (gitlab.torproject.org issue #40783).

## Development Commands

### Cloudflare Worker Development & Deployment

```bash
# Local development with hot reload
npm run dev
# or: wrangler dev

# Deploy to production
npm run deploy
# or: wrangler deploy

# Deploy to staging environment
npm run deploy:staging

# Deploy to production environment
npm run deploy:production

# View real-time logs
npm run tail
# or: wrangler tail

# Login to Cloudflare
wrangler login
```

### Frontend Development

```bash
# Serve frontend locally on port 3000
npm run serve
# or: npx serve . -p 3000
```

### Google Cloud Backend

```bash
# Build Docker container (requires PROJECT_ID env var)
npm run gcp:build
# or: docker build -t gcr.io/$PROJECT_ID/katarakt-backend .

# Push to Google Container Registry
npm run gcp:push
# or: docker push gcr.io/$PROJECT_ID/katarakt-backend

# Deploy to Cloud Run
npm run gcp:deploy
# or: gcloud run services replace google-cloud-run.yaml
```

## Architecture

### Three-Layer Protection Model

``` txt
Browser (Client) → Cloudflare Edge → Google Cloud Backend
```

**Client Layer** (`katarakt-worker.js`):

- Service Worker that intercepts all browser requests
- Blocks trackers, cryptominers, and fingerprinting scripts
- Enforces HTTPS upgrades
- Sanitizes referrer headers
- Analyzes JavaScript for malicious patterns
- Communicates with main thread via message passing

**Edge Layer** (`cloudflare-worker.js`):

- Cloudflare Worker running at the edge
- Bot detection via User-Agent and header analysis
- Injects comprehensive fingerprint protection scripts into HTML
- Applies security headers (CSP, HSTS, COEP, COOP, etc.)
- Blocks tracker domains at network level
- Provides API endpoints for health checks, config export, and threat reporting

**Backend Layer** (`google-cloud-run.yaml`):

- Google Cloud Run service configuration
- Cloud Armor security policies (rate limiting, geo-blocking, bot rules)
- Secret management for API tokens
- Auto-scaling configuration (0-100 instances)

### File Structure

- `index.html` - React-based SPA dashboard with real-time protection statistics
- `katarakt-worker.js` - Browser Service Worker (client-side protection)
- `cloudflare-worker.js` - Cloudflare Edge Worker (edge protection + script injection)
- `wrangler.toml` - Cloudflare Worker deployment configuration
- `google-cloud-run.yaml` - Google Cloud Run service manifest + Cloud Armor policies
- `package.json` - Node.js dependencies and npm scripts

## Key Implementation Details

### Fingerprint Protection Vectors

The edge worker injects JavaScript that spoofs/blocks these fingerprinting vectors:

1. **Canvas Fingerprinting**: Noise injection into `toDataURL()` and `getImageData()`
2. **WebGL Fingerprinting**: Spoofs GPU vendor/renderer, blocks `readPixels()`
3. **Audio Fingerprinting**: Intercepts AudioContext oscillator/analyser patterns
4. **Navigator Properties**: Normalizes `hardwareConcurrency`, `deviceMemory`, `platform`, hides plugins/mimeTypes
5. **Screen Properties**: Normalizes resolution and color depth (letterboxing)
6. **Timezone**: Forces UTC to prevent timezone-based fingerprinting
7. **Battery API**: Blocks battery status queries
8. **Network Info API**: Blocks connection information
9. **Performance API**: Reduces timing precision (Spectre mitigation)
10. **Text Metrics**: Rounds measurements to reduce uniqueness
11. **ClientRects**: Rounds bounding box measurements
12. **Speech Synthesis**: Returns empty voice list

### Configuration Export

The edge worker can export hardened browser configurations:

- **Firefox** (`/api/export/userjs`): 150+ `user_pref()` settings based on Mullvad/Tor Browser
- **Chrome** (`/api/export/policies`): Enterprise policies JSON for Chrome/Chromium browsers

These configs disable telemetry, enforce tracking protection, enable first-party isolation, configure DNS-over-HTTPS, and apply all the fingerprinting countermeasures supported by the browser.

### Message Passing Architecture

The browser Service Worker communicates with the main thread using `postMessage()`:

**Commands to Worker:**

- `GET_STATS` - Request current protection statistics
- `UPDATE_CONFIG` - Modify runtime configuration
- `RESET_STATS` - Clear statistics counters
- `GET_CONFIG` - Retrieve current configuration

**Events from Worker:**

- `TRACKER_BLOCKED` - Tracker domain was blocked
- `CRYPTOMINER_BLOCKED` - Cryptomining script was blocked
- `FINGERPRINT_BLOCKED` - Fingerprinting script was blocked
- `SUSPICIOUS_SCRIPT` - Script contains fingerprinting patterns
- `STATS` - Current statistics data
- `CONFIG` - Current configuration data

### Deployment Considerations

**Cloudflare:**

- The worker runs on all Cloudflare edge locations by default
- `compatibility_date` is set to "2024-01-01" with `nodejs_compat` flag
- Supports optional KV namespace for threat intelligence caching
- Daily cron trigger at midnight UTC for maintenance tasks

**Google Cloud:**

- Cloud Run service uses gen2 execution environment
- CPU boost enabled for startup performance
- Container concurrency: 80 requests per instance
- Secrets management via Secret Manager for API tokens
- Health checks on `/api/health` endpoint
- Cloud Armor provides WAF and DDoS protection

## Security Notes

This codebase implements defensive security tooling for authorized use cases (pentesting, security research, browser hardening). The fingerprint protection techniques are designed to protect user privacy, not to enable malicious activity.

The bot detection and blocking mechanisms in the Cloudflare Worker can be aggressive. When testing or developing, you may need to temporarily disable bot detection or add your IP to an allowlist.

## Configuration Files

- `wrangler.toml`: Defines Cloudflare Worker settings, environment variables, cron triggers, and optional KV/R2/Durable Objects bindings
- `google-cloud-run.yaml`: Defines Cloud Run service spec, Cloud Armor security policy, and domain mapping
- `package.json`: Defines npm scripts for common operations across all deployment targets

## Browser Compatibility

**Service Worker** (`katarakt-worker.js`):

- Requires modern browser with Service Worker support
- Chrome/Edge 40+, Firefox 44+, Safari 11.1+

**Fingerprint Protection Scripts** (injected by edge worker):

- Targets APIs present in Chrome, Firefox, Safari
- Gracefully handles missing APIs via try/catch blocks
- Based on techniques from Tor Browser (Firefox-based) but adapted for Chromium

## API Endpoints

All endpoints are served by the Cloudflare Worker:

- `GET /api/health` - Health check (returns status, version, timestamp)
- `GET /api/status` - Protection status and statistics
- `GET /api/export/userjs` - Download Firefox user.js configuration
- `GET /api/export/policies` - Download Chrome enterprise policies JSON
- `POST /api/report` - Submit threat report (consumed by worker for logging)
