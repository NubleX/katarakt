/**
 * KATARAKT - Browser Service Worker
 * 
 * Client-side security worker that monitors and protects browser activity.
 * Runs persistently to intercept requests and apply security policies.
 */
// Brought to you by ID ArtCraft Cybersecurity Labs
// https://www.idarti.com
// 2025 ID ArtCraft / NubleX / Igor Dunaev. All rights reserved.
// ## Donations are welcomed
//
// BTC: bc1qazmag6xrffm6p9yxxs5wzq93wqds0jd7wj0zkq
// ETH: 0x3F66535A08A0A268008F7634ec8cF4f3678C3c2F
//
// Security headers inspired by TOR and Mullvad.

const KATARAKT_VERSION = '1.0.0';
const CACHE_NAME = `katarakt-v${KATARAKT_VERSION}`;

// Security configuration
const CONFIG = {
  blockTrackers: true,
  blockFingerprinting: true,
  enforceHTTPS: true,
  blockWebRTC: true,
  sanitizeReferrer: true,
  blockCryptominers: true,
};

// Known tracker patterns
const TRACKER_PATTERNS = [
  /google-analytics\.com/i,
  /googletagmanager\.com/i,
  /doubleclick\.net/i,
  /facebook\.net/i,
  /facebook\.com\/tr/i,
  /connect\.facebook/i,
  /pixel\.facebook/i,
  /analytics\./i,
  /tracker\./i,
  /tracking\./i,
  /beacon\./i,
  /telemetry\./i,
  /metrics\./i,
  /scorecardresearch\.com/i,
  /quantserve\.com/i,
  /newrelic\.com/i,
  /hotjar\.com/i,
  /mouseflow\.com/i,
  /fullstory\.com/i,
  /logrocket\.com/i,
  /segment\.com/i,
  /segment\.io/i,
  /mixpanel\.com/i,
  /amplitude\.com/i,
  /heap\.io/i,
  /optimizely\.com/i,
  /criteo\./i,
  /taboola\./i,
  /outbrain\./i,
  /adnxs\.com/i,
  /adsrvr\.org/i,
  /pubmatic\.com/i,
  /rubiconproject\.com/i,
  /openx\.net/i,
  /casalemedia\.com/i,
  /advertising\.com/i,
];

// Cryptominer patterns
const CRYPTOMINER_PATTERNS = [
  /coinhive/i,
  /coin-hive/i,
  /cryptoloot/i,
  /crypto-loot/i,
  /minero\.cc/i,
  /webmine\.cz/i,
  /authedmine/i,
  /ppoi\.org/i,
  /cryptonight/i,
  /jsecoin/i,
];

// Fingerprinting script patterns
const FINGERPRINT_PATTERNS = [
  /fingerprintjs/i,
  /clientjs/i,
  /evercookie/i,
  /supercookie/i,
  /device-uuid/i,
  /browserleaks/i,
];

// Stats tracking
let stats = {
  trackersBlocked: 0,
  scriptsAnalyzed: 0,
  fingerprintsSpoofed: 0,
  requestsProtected: 0,
  cryptominersBlocked: 0,
  httpsUpgrades: 0,
};

// Message handling from main thread
self.addEventListener('message', (event) => {
  const { type, data } = event.data || {};
  const replyPort = event.ports && event.ports[0];
  
  switch (type) {
    case 'GET_STATS':
      if (replyPort) replyPort.postMessage({ type: 'STATS', data: stats });
      break;
      
    case 'UPDATE_CONFIG':
      // Accept only known settings with boolean values (no prototype keys, no new settings)
      if (data && typeof data === 'object') {
        for (const key of Object.keys(CONFIG)) {
          if (Object.prototype.hasOwnProperty.call(data, key) && typeof data[key] === 'boolean') {
            CONFIG[key] = data[key];
          }
        }
      }
      break;
      
    case 'RESET_STATS':
      stats = {
        trackersBlocked: 0,
        scriptsAnalyzed: 0,
        fingerprintsSpoofed: 0,
        requestsProtected: 0,
        cryptominersBlocked: 0,
        httpsUpgrades: 0,
      };
      break;
      
    case 'GET_CONFIG':
      if (replyPort) replyPort.postMessage({ type: 'CONFIG', data: CONFIG });
      break;
  }
});

// Install event
self.addEventListener('install', (event) => {
  console.log(`[Katarakt] Service Worker v${KATARAKT_VERSION} installing...`);
  
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll([
        '/katarakt-protection.js',
      ]);
    })
  );
  
  self.skipWaiting();
});

// Activate event
self.addEventListener('activate', (event) => {
  console.log(`[Katarakt] Service Worker v${KATARAKT_VERSION} activated`);
  
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      );
    })
  );
  
  self.clients.claim();
});

// Fetch event - intercept all requests
self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);
  
  // Skip internal requests
  if (url.protocol === 'chrome-extension:' || url.protocol === 'moz-extension:') {
    return;
  }
  
  event.respondWith(handleRequest(request, url));
});

/**
 * Main request handler
 */
async function handleRequest(request, url) {
  stats.requestsProtected++;
  
  // Check for trackers
  if (CONFIG.blockTrackers && isTracker(url.href)) {
    stats.trackersBlocked++;
    notifyClients('TRACKER_BLOCKED', { url: url.href });
    return new Response(null, { status: 204 });
  }
  
  // Check for cryptominers
  if (CONFIG.blockCryptominers && isCryptominer(url.href)) {
    stats.cryptominersBlocked++;
    notifyClients('CRYPTOMINER_BLOCKED', { url: url.href });
    return new Response(null, { status: 204 });
  }
  
  // Check for fingerprinting scripts
  if (CONFIG.blockFingerprinting && isFingerprinter(url.href)) {
    stats.fingerprintsSpoofed++;
    notifyClients('FINGERPRINT_BLOCKED', { url: url.href });
    return new Response(null, { status: 204 });
  }
  
  // Upgrade HTTP to HTTPS
  if (CONFIG.enforceHTTPS && url.protocol === 'http:') {
    const httpsUrl = url.href.replace('http:', 'https:');
    stats.httpsUpgrades++;
    return Response.redirect(httpsUrl, 301);
  }
  
  // Modify request headers
  const modifiedRequest = modifyRequest(request);
  
  try {
    let response = await fetch(modifiedRequest);
    
    // Analyze scripts
    const contentType = response.headers.get('Content-Type') || '';
    if (contentType.includes('javascript')) {
      stats.scriptsAnalyzed++;
      response = await analyzeScript(response, url);
    }
    
    // Modify response headers
    return modifyResponse(response);
  } catch (error) {
    console.error('[Katarakt] Fetch error:', error);
    return fetch(request);
  }
}

/**
 * Modify outgoing request headers
 */
function modifyRequest(request) {
  const headers = new Headers(request.headers);
  
  // Sanitize referrer
  if (CONFIG.sanitizeReferrer) {
    const referrer = headers.get('Referer');
    if (referrer) {
      try {
        const refUrl = new URL(referrer);
        headers.set('Referer', refUrl.origin);
      } catch (e) {
        headers.delete('Referer');
      }
    }
  }
  
  // Remove tracking headers
  headers.delete('X-Requested-With');
  
  // Add DNT header
  headers.set('DNT', '1');
  headers.set('Sec-GPC', '1');
  
  return new Request(request.url, {
    method: request.method,
    headers: headers,
    body: request.body,
    mode: request.mode,
    credentials: request.credentials,
    cache: request.cache,
    redirect: request.redirect,
    referrer: request.referrer,
    referrerPolicy: 'strict-origin-when-cross-origin',
    integrity: request.integrity,
  });
}

/**
 * Modify response headers for security
 */
function modifyResponse(response) {
  const headers = new Headers(response.headers);
  
  // Add security headers
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Katarakt-Protected', 'true');
  
  // Remove tracking headers
  headers.delete('X-FB-Debug');
  headers.delete('X-Google-Cache-Control');
  
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: headers,
  });
}

/**
 * Check if URL is a tracker
 */
function isTracker(url) {
  return TRACKER_PATTERNS.some(pattern => pattern.test(url));
}

/**
 * Check if URL is a cryptominer
 */
function isCryptominer(url) {
  return CRYPTOMINER_PATTERNS.some(pattern => pattern.test(url));
}

/**
 * Check if URL is a fingerprinting script
 */
function isFingerprinter(url) {
  return FINGERPRINT_PATTERNS.some(pattern => pattern.test(url));
}

/**
 * Analyze JavaScript for malicious patterns
 */
async function analyzeScript(response, url) {
  try {
    const text = await response.text();
    
    // Check for fingerprinting code
    const fingerprintPatterns = [
      /canvas\.toDataURL/,
      /getImageData\s*\(/,
      /webgl.*getParameter/i,
      /AudioContext/,
      /createOscillator/,
      /navigator\.plugins/,
      /navigator\.mimeTypes/,
      /screen\.colorDepth/,
      /devicePixelRatio/,
    ];
    
    let isSuspicious = false;
    for (const pattern of fingerprintPatterns) {
      if (pattern.test(text)) {
        isSuspicious = true;
        break;
      }
    }
    
    if (isSuspicious) {
      notifyClients('SUSPICIOUS_SCRIPT', { url: url.href });
    }
    
    return new Response(text, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  } catch (e) {
    return response;
  }
}

/**
 * Notify all clients of security events
 */
async function notifyClients(type, data) {
  const clients = await self.clients.matchAll();
  clients.forEach(client => {
    client.postMessage({
      type: type,
      data: data,
      timestamp: Date.now(),
    });
  });
}

// Background sync for threat reporting
self.addEventListener('sync', (event) => {
  if (event.tag === 'threat-report') {
    event.waitUntil(sendThreatReport());
  }
});

/**
 * Send accumulated threat reports to backend
 */
async function sendThreatReport() {
  try {
    await fetch('/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        stats: stats,
        timestamp: Date.now(),
        version: KATARAKT_VERSION,
      }),
    });
  } catch (e) {
    console.error('[Katarakt] Failed to send threat report:', e);
  }
}

// Periodic stats cleanup
setInterval(() => {
  // Reset daily stats at midnight
  const now = new Date();
  if (now.getHours() === 0 && now.getMinutes() === 0) {
    const dailyReport = { ...stats };
    sendThreatReport().then(() => {
      stats = {
        trackersBlocked: 0,
        scriptsAnalyzed: 0,
        fingerprintsSpoofed: 0,
        requestsProtected: 0,
        cryptominersBlocked: 0,
        httpsUpgrades: 0,
      };
    });
  }
}, 60000);

console.log(`[Katarakt] Service Worker v${KATARAKT_VERSION} ready`);
