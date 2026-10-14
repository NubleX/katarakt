import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import worker from '../cloudflare-worker.js';

const BROWSER_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0',
  'Accept-Language': 'en-US,en;q=0.5',
  'Accept-Encoding': 'gzip, deflate, br',
};

function withOrigin(response, fn) {
  const original = globalThis.fetch;
  globalThis.fetch = async () => response;
  return Promise.resolve(fn()).finally(() => {
    globalThis.fetch = original;
  });
}

function call(path, init = {}, env = {}) {
  const headers = { ...BROWSER_HEADERS, ...(init.headers || {}) };
  return worker.fetch(new Request(`https://shield.example.test${path}`, { ...init, headers }), env, {});
}

const validReport = {
  stats: {
    trackersBlocked: 1,
    scriptsAnalyzed: 2,
    fingerprintsSpoofed: 3,
    requestsProtected: 4,
    cryptominersBlocked: 5,
    httpsUpgrades: 6,
  },
  timestamp: 1760000000000,
  version: '1.0.0',
};

function postReport(body, headers = { 'Content-Type': 'application/json' }) {
  return call('/api/report', { method: 'POST', headers, body });
}

test('HTML responses get the fingerprint script injected', async () => {
  const origin = new Response('<html><head></head><body>hi</body></html>', {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
  await withOrigin(origin, async () => {
    const res = await call('/');
    const body = await res.text();
    assert.match(body, /Katarakt: Fingerprint protection active/);
    assert.equal(res.headers.get('X-Katarakt-Protected'), 'true');
    assert.equal(res.headers.get('X-XSS-Protection'), '0');
  });
});

test('binary responses pass through byte-for-byte', async () => {
  const bytes = new Uint8Array([0xff, 0xfe, 0x00, 0x80, 0x81, 0xc0, 0xaf, 0x00, 0x42]);
  await withOrigin(new Response(bytes, { headers: { 'Content-Type': 'image/png' } }), async () => {
    const res = await call('/logo.png');
    assert.deepEqual(new Uint8Array(await res.arrayBuffer()), bytes);
    assert.equal(res.headers.get('X-Katarakt-Protected'), 'true');
  });
});

test('CSP trusts exact pinned script URLs, not the whole of unpkg.com', async () => {
  await withOrigin(new Response('<html><head></head></html>', { headers: { 'Content-Type': 'text/html' } }), async () => {
    const csp = (await call('/')).headers.get('Content-Security-Policy');
    const scriptSrc = csp.split('; ').find((d) => d.startsWith('script-src '));
    assert.ok(!/(^|\s)https:\/\/unpkg\.com(\s|$)/.test(scriptSrc), 'bare unpkg.com origin must not be allowed');
    assert.match(scriptSrc, /https:\/\/unpkg\.com\/react@18\.3\.1\//);
    assert.ok(!csp.includes("'unsafe-eval'"));
    const connectSrc = csp.split('; ').find((d) => d.startsWith('connect-src '));
    assert.equal(connectSrc, "connect-src 'self'");
  });
});

test('index.html scripts are version-pinned, SRI-protected and allowed by the CSP', async () => {
  const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
  const tags = [...html.matchAll(/<script[^>]+src="(https:\/\/unpkg\.com[^"]+)"[^>]*>/g)];
  assert.ok(tags.length >= 3);
  await withOrigin(new Response('<html><head></head></html>', { headers: { 'Content-Type': 'text/html' } }), async () => {
    const csp = (await call('/')).headers.get('Content-Security-Policy');
    for (const [tag, src] of tags) {
      assert.match(src, /@\d+\.\d+\.\d+\//, `${src} must pin an exact version`);
      assert.match(tag, /integrity="sha384-[A-Za-z0-9+/=]+"/, `${src} needs an integrity hash`);
      assert.match(tag, /crossorigin="anonymous"/);
      assert.ok(csp.includes(src), `${src} must be listed in the CSP`);
    }
  });
});

test('bot blocking is off by default and on when BOT_BLOCKING=on', async () => {
  const html = () => new Response('<html><head></head></html>', { headers: { 'Content-Type': 'text/html' } });
  await withOrigin(html(), async () => {
    const res = await call('/', { headers: { 'User-Agent': 'curl/8.0' } });
    assert.equal(res.status, 200);
  });
  await withOrigin(html(), async () => {
    const res = await call('/', { headers: { 'User-Agent': 'curl/8.0' } }, { BOT_BLOCKING: 'on' });
    assert.equal(res.status, 403);
  });
});

test('tracker blocking matches the domain and its subdomains only', async () => {
  const ok = () => new Response('x', { headers: { 'Content-Type': 'text/plain' } });
  const original = globalThis.fetch;
  globalThis.fetch = async () => ok();
  try {
    const direct = await worker.fetch(new Request('https://doubleclick.net/', { headers: BROWSER_HEADERS }), {}, {});
    const sub = await worker.fetch(new Request('https://ad.doubleclick.net/', { headers: BROWSER_HEADERS }), {}, {});
    const lookalike = await worker.fetch(new Request('https://notdoubleclick.net/', { headers: BROWSER_HEADERS }), {}, {});
    assert.equal(direct.status, 204);
    assert.equal(sub.status, 204);
    assert.equal(lookalike.status, 200);
  } finally {
    globalThis.fetch = original;
  }
});

test('/api/status reports only what the Worker does and has no fake stats', async () => {
  const res = await call('/api/status', {}, { BOT_BLOCKING: 'on' });
  const data = await res.json();
  assert.equal(data.edge.botBlocking, true);
  assert.equal(data.edge.cloudflareBotManagementData, false);
  assert.ok(!('stats' in data));
  assert.ok(!JSON.stringify(data).includes('ddosProtection'));
  assert.ok(!JSON.stringify(data).includes('wafRules'));
});

test('/api/report accepts a valid report and logs only the sanitized fields', async () => {
  const logged = [];
  const original = console.log;
  console.log = (...args) => logged.push(args.join(' '));
  try {
    const res = await postReport(JSON.stringify({ ...validReport, injected: 'x'.repeat(100), secret: 'nope' }));
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { received: true });
  } finally {
    console.log = original;
  }
  const line = logged.find((l) => l.startsWith('Threat report:'));
  assert.ok(line);
  assert.ok(!line.includes('injected') && !line.includes('secret'));
});

test('/api/report rejects bad requests', async () => {
  assert.equal((await call('/api/report')).status, 405);
  assert.equal((await postReport('{}', { 'Content-Type': 'text/plain' })).status, 415);
  assert.equal((await postReport('{not json')).status, 400);
  assert.equal((await postReport('[]')).status, 400);
  assert.equal((await postReport(JSON.stringify({ ...validReport, version: 'x'.repeat(33) }))).status, 400);
  assert.equal(
    (await postReport(JSON.stringify({ ...validReport, stats: { ...validReport.stats, httpsUpgrades: 'many' } }))).status,
    400,
  );
});

test('/api/report enforces the size cap with and without Content-Length', async () => {
  const big = JSON.stringify({ ...validReport, pad: 'x'.repeat(20 * 1024) });
  assert.equal((await postReport(big)).status, 413);
  const chunked = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(big));
      controller.close();
    },
  });
  const res = await worker.fetch(
    new Request('https://shield.example.test/api/report', {
      method: 'POST',
      headers: { ...BROWSER_HEADERS, 'Content-Type': 'application/json' },
      body: chunked,
      duplex: 'half',
    }),
    {},
    {},
  );
  assert.equal(res.status, 413);
});
