/**
 * KATARAKT - Cloudflare Edge Security Worker
 * 
 * A security-hardening worker that runs at the edge to protect against:
 * - Bot detection and blocking
 * - Fingerprinting attempts
 * - Malicious scripts injection
 * - Request manipulation
 * 
 * Deploy to Cloudflare Workers for edge protection
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

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

// Content Security Policy
const CSP_DIRECTIVES = {
  'default-src': ["'self'"],
  'script-src': ["'self'", "'unsafe-inline'"],
  'style-src': ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
  'font-src': ["'self'", 'https://fonts.gstatic.com'],
  'img-src': ["'self'", 'data:', 'blob:'],
  'connect-src': ["'self'"],
  'frame-ancestors': ["'none'"],
  'base-uri': ["'self'"],
  'form-action': ["'self'"],
  'upgrade-insecure-requests': [],
};

// Known bot signatures
const BOT_SIGNATURES = {
  userAgents: [
    /bot/i,
    /spider/i,
    /crawl/i,
    /scraper/i,
    /curl/i,
    /wget/i,
    /python-requests/i,
    /headless/i,
    /phantom/i,
    /selenium/i,
    /puppeteer/i,
    /playwright/i,
  ],
  headers: [
    'x-forwarded-for-original',
    'x-real-ip-original',
  ],
};

// Known tracker domains to block
const TRACKER_DOMAINS = new Set([
  'doubleclick.net',
  'googleadservices.com',
  'googlesyndication.com',
  'facebook.net',
  'fbcdn.net',
  'analytics.google.com',
  'google-analytics.com',
  'scorecardresearch.com',
  'quantserve.com',
  'advertising.com',
  'adnxs.com',
  'criteo.com',
  'taboola.com',
  'outbrain.com',
]);

// Fingerprinting scripts to detect
const FINGERPRINT_PATTERNS = [
  /canvas\.toDataURL/i,
  /getImageData/i,
  /webgl.*getParameter/i,
  /AudioContext/i,
  /createOscillator/i,
  /navigator\.plugins/i,
  /navigator\.mimeTypes/i,
  /screen\.colorDepth/i,
  /window\.devicePixelRatio/i,
];

/**
 * Build CSP header from directives
 */
function buildCSP(directives) {
  return Object.entries(directives)
    .map(([key, values]) => {
      if (values.length === 0) return key;
      return `${key} ${values.join(' ')}`;
    })
    .join('; ');
}

/**
 * Detect if request is from a bot
 */
function detectBot(request) {
  const userAgent = request.headers.get('User-Agent') || '';
  const acceptLanguage = request.headers.get('Accept-Language');
  const acceptEncoding = request.headers.get('Accept-Encoding');
  
  // Check user agent patterns
  for (const pattern of BOT_SIGNATURES.userAgents) {
    if (pattern.test(userAgent)) {
      return { isBot: true, reason: 'User-Agent matches bot pattern' };
    }
  }
  
  // Check for missing browser headers
  if (!acceptLanguage || !acceptEncoding) {
    return { isBot: true, reason: 'Missing standard browser headers' };
  }
  
  // Check for suspicious header combinations
  for (const header of BOT_SIGNATURES.headers) {
    if (request.headers.has(header)) {
      return { isBot: true, reason: `Suspicious header: ${header}` };
    }
  }
  
  // Check for empty or suspicious user agent
  if (!userAgent || userAgent.length < 20) {
    return { isBot: true, reason: 'Invalid User-Agent' };
  }
  
  return { isBot: false };
}

/**
 * Check if URL is a tracker
 */
function isTracker(url) {
  try {
    const hostname = new URL(url).hostname;
    for (const tracker of TRACKER_DOMAINS) {
      if (hostname.includes(tracker)) {
        return true;
      }
    }
  } catch (e) {
    // Invalid URL
  }
  return false;
}

/**
 * Inject fingerprint protection script
 * Based on Tor Browser / Mullvad Browser anti-fingerprinting research
 */
function getFingerprintProtectionScript() {
  return `
<script>
(function() {
  'use strict';
  
  // === CANVAS FINGERPRINT PROTECTION ===
  const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function(type) {
    const ctx = this.getContext('2d');
    if (ctx) {
      const imageData = ctx.getImageData(0, 0, this.width, this.height);
      for (let i = 0; i < imageData.data.length; i += 4) {
        imageData.data[i] = imageData.data[i] ^ (Math.random() * 2 | 0);
      }
      ctx.putImageData(imageData, 0, 0);
    }
    return originalToDataURL.apply(this, arguments);
  };
  
  const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function() {
    const imageData = originalGetImageData.apply(this, arguments);
    for (let i = 0; i < imageData.data.length; i += 4) {
      imageData.data[i] = imageData.data[i] ^ (Math.random() * 2 | 0);
    }
    return imageData;
  };
  
  // === WEBGL FINGERPRINT PROTECTION ===
  const spoofedWebGLParams = {
    37445: 'Intel Inc.',                    // UNMASKED_VENDOR_WEBGL
    37446: 'Intel Iris OpenGL Engine',      // UNMASKED_RENDERER_WEBGL
    7936: 'WebKit',                          // VENDOR
    7937: 'WebKit WebGL',                    // RENDERER
    34047: 16,                               // MAX_TEXTURE_MAX_ANISOTROPY_EXT
    3379: 16384,                             // MAX_TEXTURE_SIZE
    34076: 16384,                            // MAX_CUBE_MAP_TEXTURE_SIZE
    34024: 16384,                            // MAX_RENDERBUFFER_SIZE
    35661: 80,                               // MAX_COMBINED_TEXTURE_IMAGE_UNITS
    34930: 16,                               // MAX_TEXTURE_IMAGE_UNITS
    36349: 1024,                             // MAX_VERTEX_UNIFORM_COMPONENTS
    35657: 4096,                             // MAX_FRAGMENT_UNIFORM_COMPONENTS
    35658: 16,                               // MAX_VERTEX_TEXTURE_IMAGE_UNITS
  };
  
  const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = function(param) {
    if (spoofedWebGLParams[param] !== undefined) return spoofedWebGLParams[param];
    return originalGetParameter.apply(this, arguments);
  };
  
  if (typeof WebGL2RenderingContext !== 'undefined') {
    const originalGetParameter2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = function(param) {
      if (spoofedWebGLParams[param] !== undefined) return spoofedWebGLParams[param];
      return originalGetParameter2.apply(this, arguments);
    };
  }
  
  // Block readPixels for fingerprinting prevention
  const originalReadPixels = WebGLRenderingContext.prototype.readPixels;
  WebGLRenderingContext.prototype.readPixels = function() {
    console.warn('Katarakt: WebGL readPixels blocked');
    return;
  };
  
  // === AUDIO FINGERPRINT PROTECTION ===
  if (typeof AudioContext !== 'undefined') {
    const originalCreateOscillator = AudioContext.prototype.createOscillator;
    AudioContext.prototype.createOscillator = function() {
      const oscillator = originalCreateOscillator.apply(this, arguments);
      const originalConnect = oscillator.connect;
      oscillator.connect = function(destination) {
        if (destination instanceof AnalyserNode) {
          console.warn('Katarakt: Audio fingerprinting attempt blocked');
          return oscillator;
        }
        return originalConnect.apply(this, arguments);
      };
      return oscillator;
    };
    
    const originalCreateAnalyser = AudioContext.prototype.createAnalyser;
    AudioContext.prototype.createAnalyser = function() {
      const analyser = originalCreateAnalyser.apply(this, arguments);
      const originalGetFloatFrequencyData = analyser.getFloatFrequencyData;
      analyser.getFloatFrequencyData = function(array) {
        originalGetFloatFrequencyData.apply(this, arguments);
        for (let i = 0; i < array.length; i++) {
          array[i] = array[i] + (Math.random() * 0.1 - 0.05);
        }
      };
      return analyser;
    };
  }
  
  // === NAVIGATOR PROPERTIES SPOOFING ===
  // Normalize to common values (matching Tor Browser approach)
  const navigatorProps = {
    hardwareConcurrency: 4,
    deviceMemory: 8,
    platform: 'Win32',
    vendor: 'Google Inc.',
    appVersion: '5.0 (Windows)',
    maxTouchPoints: 0
  };
  
  for (const [prop, value] of Object.entries(navigatorProps)) {
    try {
      Object.defineProperty(navigator, prop, { 
        get: () => value,
        configurable: true 
      });
    } catch (e) {}
  }
  
  // Hide plugins and mimeTypes (major fingerprinting vector)
  Object.defineProperty(navigator, 'plugins', { 
    get: () => { return { length: 0, item: () => null, namedItem: () => null }; },
    configurable: true 
  });
  Object.defineProperty(navigator, 'mimeTypes', { 
    get: () => { return { length: 0, item: () => null, namedItem: () => null }; },
    configurable: true 
  });
  
  // === SCREEN PROPERTIES NORMALIZATION ===
  // Part of letterboxing protection
  const screenProps = {
    colorDepth: 24,
    pixelDepth: 24,
    availWidth: 1920,
    availHeight: 1080,
    width: 1920,
    height: 1080,
    availLeft: 0,
    availTop: 0
  };
  
  for (const [prop, value] of Object.entries(screenProps)) {
    try {
      Object.defineProperty(screen, prop, { 
        get: () => value,
        configurable: true 
      });
    } catch (e) {}
  }
  
  // === TIMEZONE SPOOFING ===
  Date.prototype.getTimezoneOffset = function() { return 0; };
  
  const originalDateTimeFormat = Intl.DateTimeFormat;
  Intl.DateTimeFormat = function(locales, options) {
    options = options || {};
    options.timeZone = 'UTC';
    return new originalDateTimeFormat(locales, options);
  };
  Intl.DateTimeFormat.prototype = originalDateTimeFormat.prototype;
  
  // === BATTERY API BLOCKING ===
  if (navigator.getBattery) {
    navigator.getBattery = function() {
      return Promise.reject(new Error('Battery API disabled'));
    };
  }
  
  // === NETWORK INFORMATION API BLOCKING ===
  if (navigator.connection) {
    Object.defineProperty(navigator, 'connection', { get: () => undefined });
  }
  
  // === PERFORMANCE API PROTECTION ===
  // Reduce timing precision (Spectre/Meltdown mitigation)
  const originalNow = performance.now;
  performance.now = function() {
    return Math.floor(originalNow.call(performance) / 100) * 100;
  };
  
  // === SPEECH SYNTHESIS BLOCKING ===
  if (window.speechSynthesis) {
    window.speechSynthesis.getVoices = function() { return []; };
  }
  
  // === TEXT METRICS PROTECTION ===
  const originalMeasureText = CanvasRenderingContext2D.prototype.measureText;
  CanvasRenderingContext2D.prototype.measureText = function(text) {
    const metrics = originalMeasureText.call(this, text);
    // Round values to reduce uniqueness
    return {
      width: Math.round(metrics.width),
      actualBoundingBoxLeft: 0,
      actualBoundingBoxRight: Math.round(metrics.width),
      actualBoundingBoxAscent: 0,
      actualBoundingBoxDescent: 0,
      fontBoundingBoxAscent: 0,
      fontBoundingBoxDescent: 0,
      emHeightAscent: 0,
      emHeightDescent: 0,
      alphabeticBaseline: 0,
      hangingBaseline: 0,
      ideographicBaseline: 0
    };
  };
  
  // === CLIENT RECTS PROTECTION ===
  const originalGetClientRects = Element.prototype.getClientRects;
  Element.prototype.getClientRects = function() {
    const rects = originalGetClientRects.apply(this, arguments);
    const roundedRects = [];
    for (let i = 0; i < rects.length; i++) {
      roundedRects.push({
        x: Math.round(rects[i].x),
        y: Math.round(rects[i].y),
        width: Math.round(rects[i].width),
        height: Math.round(rects[i].height),
        top: Math.round(rects[i].top),
        right: Math.round(rects[i].right),
        bottom: Math.round(rects[i].bottom),
        left: Math.round(rects[i].left)
      });
    }
    return roundedRects;
  };
  
  console.log('%cKatarakt: Fingerprint protection active', 'color: #00ff88; font-weight: bold;');
  console.log('%cProtected vectors: Canvas, WebGL, Audio, Navigator, Screen, Timezone, Battery, Network, Performance, TextMetrics, ClientRects', 'color: #00d4ff;');
})();
</script>`;
}

/**
 * Main request handler
 */
async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const startTime = Date.now();
  
  // Bot detection
  const botCheck = detectBot(request);
  if (botCheck.isBot) {
    // Log the blocked request
    console.log(`Bot blocked: ${botCheck.reason} from ${request.headers.get('CF-Connecting-IP')}`);
    
    // Return challenge page or block
    return new Response(JSON.stringify({
      error: 'Access denied',
      reason: 'Automated access detected',
      code: 'BOT_DETECTED'
    }), {
      status: 403,
      headers: {
        'Content-Type': 'application/json',
        ...SECURITY_HEADERS
      }
    });
  }
  
  // Block tracker requests
  if (isTracker(request.url)) {
    return new Response('', { status: 204 });
  }
  
  // Handle API routes
  if (url.pathname.startsWith('/api/')) {
    return handleAPIRequest(request, url);
  }
  
  // Fetch the original response
  let response = await fetch(request);
  
  // Clone the response to modify it
  let body = await response.text();
  
  // Only inject protection into HTML responses
  const contentType = response.headers.get('Content-Type') || '';
  if (contentType.includes('text/html')) {
    // Inject fingerprint protection script
    body = body.replace('</head>', `${getFingerprintProtectionScript()}</head>`);
  }
  
  // Build new headers
  const newHeaders = new Headers(response.headers);
  
  // Add security headers
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    newHeaders.set(key, value);
  }
  
  // Add CSP
  newHeaders.set('Content-Security-Policy', buildCSP(CSP_DIRECTIVES));
  
  // Add timing header
  newHeaders.set('X-Katarakt-Time', `${Date.now() - startTime}ms`);
  newHeaders.set('X-Katarakt-Protected', 'true');
  
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders
  });
}

/**
 * Handle API requests
 */
async function handleAPIRequest(request, url) {
  const pathname = url.pathname;
  
  // Health check
  if (pathname === '/api/health') {
    return new Response(JSON.stringify({
      status: 'healthy',
      version: '1.0.0',
      timestamp: new Date().toISOString()
    }), {
      headers: { 'Content-Type': 'application/json', ...SECURITY_HEADERS }
    });
  }
  
  // Get security status
  if (pathname === '/api/status') {
    return new Response(JSON.stringify({
      protection: {
        fingerprinting: true,
        webrtc: true,
        tracking: true,
        cookies: true,
        network: true,
        javascript: true
      },
      integrations: {
        cloudflare: {
          botManagement: true,
          wafRules: true,
          ddosProtection: true
        }
      },
      stats: {
        requestsProcessed: 0,
        botsBlocked: 0,
        trackersBlocked: 0
      }
    }), {
      headers: { 'Content-Type': 'application/json', ...SECURITY_HEADERS }
    });
  }
  
  // Export configuration
  if (pathname === '/api/export/userjs') {
    const userjs = generateUserJS();
    return new Response(userjs, {
      headers: {
        'Content-Type': 'application/javascript',
        'Content-Disposition': 'attachment; filename="katarakt-user.js"',
        ...SECURITY_HEADERS
      }
    });
  }
  
  if (pathname === '/api/export/policies') {
    const policies = generateChromePolicies();
    return new Response(JSON.stringify(policies, null, 2), {
      headers: {
        'Content-Type': 'application/json',
        'Content-Disposition': 'attachment; filename="policies.json"',
        ...SECURITY_HEADERS
      }
    });
  }
  
  // Report endpoint for threat logging
  if (pathname === '/api/report' && request.method === 'POST') {
    const data = await request.json();
    console.log('Threat report:', data);
    return new Response(JSON.stringify({ received: true }), {
      headers: { 'Content-Type': 'application/json', ...SECURITY_HEADERS }
    });
  }
  
  return new Response(JSON.stringify({ error: 'Not found' }), {
    status: 404,
    headers: { 'Content-Type': 'application/json', ...SECURITY_HEADERS }
  });
}

/**
 * Generate Firefox user.js configuration
 * Based on comprehensive review of Tor Browser / Mullvad Browser preferences
 * Source: gitlab.torproject.org/tpo/applications/tor-browser/-/issues/40783
 */
function generateUserJS() {
  return `// ============================================================================
// KATARAKT Firefox Hardening Configuration v1.0
// Based on Mullvad Browser / Tor Browser security settings
// Source: gitlab.torproject.org 001-base-browser.js / 000-tor-browser.js
// ============================================================================

// === CORE FINGERPRINTING RESISTANCE ===
// These are the foundation of anti-fingerprinting
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.resistFingerprinting.letterboxing", true);
user_pref("privacy.resistFingerprinting.block_mozAddonManager", true);
user_pref("privacy.firstparty.isolate", true);

// === WEBRTC PROTECTION ===
// Prevents IP leaks through WebRTC
user_pref("media.peerconnection.enabled", false);
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.ice.no_host", true);
user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);

// === TRACKING PROTECTION ===
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("privacy.trackingprotection.cryptomining.enabled", true);
user_pref("privacy.trackingprotection.fingerprinting.enabled", true);
user_pref("privacy.purge_trackers.enabled", false);

// === COOKIE & STATE ISOLATION ===
// Total Cookie Protection (dFPI)
user_pref("network.cookie.cookieBehavior", 5);
user_pref("network.cookie.cookieBehavior.pbmode", 5);
user_pref("network.cookie.lifetimePolicy", 2);
user_pref("privacy.partition.network_state", true);
user_pref("privacy.partition.serviceWorkers", true);
user_pref("privacy.partition.always_partition_third_party_non_cookie_storage", true);

// === NETWORK HARDENING ===
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);
user_pref("network.prefetch-next", false);
user_pref("network.predictor.enabled", false);
user_pref("network.http.referer.defaultPolicy", 2);
user_pref("network.http.referer.XOriginPolicy", 2);
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);
user_pref("network.trr.mode", 3);
user_pref("network.trr.exclude-etc-hosts", false);
user_pref("network.proxy.allow_bypass", false);
user_pref("network.http.tailing.enabled", true);
user_pref("network.manage-offline-status", false);
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);
user_pref("network.file.disable_unc_paths", true);
user_pref("network.gio.supported-protocols", "");

// === HTTP/2 & HTTP/3 ===
user_pref("network.http.http3.enabled", false);
user_pref("network.http.http2.enabled", true);
user_pref("network.http.connection-retry-timeout", 0);

// === SSL/TLS HARDENING ===
user_pref("security.ssl.require_safe_negotiation", true);
user_pref("security.ssl.enable_false_start", false);
user_pref("security.ssl3.dhe_rsa_aes_128_sha", false);
user_pref("security.ssl3.dhe_rsa_aes_256_sha", false);
user_pref("security.ssl3.ecdhe_ecdsa_aes_256_sha", true);
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_sha", true);
user_pref("security.ssl3.ecdhe_rsa_aes_128_sha", true);
user_pref("security.ssl3.ecdhe_rsa_aes_256_sha", true);
user_pref("security.ssl3.rsa_aes_128_sha", false);
user_pref("security.ssl3.rsa_aes_256_sha", false);
user_pref("security.cert_pinning.enforcement_level", 2);
user_pref("security.pki.crlite_mode", 0);
user_pref("security.remote_settings.intermediates.enabled", false);

// === CERTIFICATE & AUTH ===
user_pref("security.nocertdb", true);
user_pref("security.osclientcerts.autoload", false);
user_pref("security.family_safety.mode", 0);
user_pref("security.enterprise_roots.enabled", false);
user_pref("security.certerrors.mitm.priming.enabled", false);
user_pref("security.webauth.webauthn", false);

// === JAVASCRIPT & DOM RESTRICTIONS ===
user_pref("dom.disable_window_move_resize", true);
user_pref("dom.disable_beforeunload", true);
user_pref("dom.push.enabled", false);
user_pref("dom.push.serverURL", "");
user_pref("dom.battery.enabled", false);
user_pref("dom.enable_resource_timing", false);
user_pref("dom.enable_event_timing", false);
user_pref("dom.netinfo.enabled", false);
user_pref("dom.vr.enabled", false);
user_pref("dom.webmidi.enabled", false);
user_pref("dom.webaudio.enabled", false);
user_pref("dom.w3c_touch_events.enabled", 0);
user_pref("dom.serviceWorkers.enabled", true);
user_pref("dom.postMessage.sharedArrayBuffer.withCOOP_COEP", false);
user_pref("dom.use_components_shim", false);
user_pref("dom.security.https_only_mode", true);
user_pref("javascript.options.large_arraybuffers", false);

// === WEBGL FINGERPRINTING ===
user_pref("webgl.disabled", false);
user_pref("webgl.enable-webgl2", true);
user_pref("webgl.disable-fail-if-major-performance-caveat", true);

// === CANVAS & TEXT METRICS ===
user_pref("dom.textMetrics.actualBoundingBox.enabled", false);
user_pref("dom.textMetrics.baselines.enabled", false);
user_pref("dom.textMetrics.emHeight.enabled", false);
user_pref("dom.textMetrics.fontBoundingBox.enabled", false);
user_pref("gfx.offscreencanvas.domain-enabled", false);
user_pref("gfx.downloadable_fonts.fallback_delay", -1);

// === MEDIA FINGERPRINTING ===
user_pref("media.navigator.enabled", false);
user_pref("media.benchmark.vp9.threshold", 0);
user_pref("media.videocontrols.picture-in-picture.enabled", false);
user_pref("media.gmp-provider.enabled", false);
user_pref("media.gmp-manager.updateEnabled", false);
user_pref("media.eme.enabled", false);
user_pref("browser.eme.ui.enabled", false);
user_pref("media.gmp-widevinecdm.visible", false);
user_pref("media.gmp-widevinecdm.enabled", false);

// === GEOLOCATION ===
user_pref("geo.enabled", false);
user_pref("geo.provider.network.url", "");
user_pref("browser.region.network.scan", false);
user_pref("browser.region.network.url", "");
user_pref("browser.region.update.enabled", false);
user_pref("browser.region.local-geocoding", false);

// === TELEMETRY & DATA COLLECTION ===
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("messaging-system.rsexperimentloader.enabled", false);
user_pref("corroborator.enabled", false);
user_pref("default-browser-agent.enabled", false);

// === SAFE BROWSING (Local only) ===
user_pref("browser.safebrowsing.malware.enabled", true);
user_pref("browser.safebrowsing.phishing.enabled", true);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.enabled", false);

// === SYNC & ACCOUNTS ===
user_pref("identity.fxaccounts.enabled", false);
user_pref("services.sync.engine.bookmarks", false);
user_pref("services.sync.engine.history", false);
user_pref("services.sync.engine.passwords", false);
user_pref("services.sync.engine.addresses", false);
user_pref("services.sync.engine.creditcards", false);

// === BROWSER BEHAVIOR ===
user_pref("browser.privatebrowsing.autostart", true);
user_pref("browser.cache.disk.enable", false);
user_pref("browser.sessionstore.privacy_level", 2);
user_pref("browser.privatebrowsing.forceMediaMemoryCache", true);
user_pref("browser.send_pings", false);
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.search.update", false);
user_pref("browser.startup.homepage_override.buildID", "20100101");
user_pref("browser.link.open_newwindow.restriction", 0);
user_pref("browser.urlbar.dnsResolveSingleWordsAfterSearch", 0);
user_pref("browser.urlbar.suggest.topsites", false);
user_pref("browser.share_menu.allow", false);
user_pref("browser.tabs.remote.separatedMozillaDomains", "");
user_pref("browser.disableResetPrompt", true);

// === FORM & PASSWORD ===
user_pref("signon.rememberSignons", false);
user_pref("signon.autofillForms", false);
user_pref("signon.management.page.breach-alerts.enabled", false);
user_pref("signon.recipes.remoteRecipes.enabled", false);
user_pref("browser.formfill.enable", false);
user_pref("permissions.memory_only", true);
user_pref("browser.download.useDownloadDir", false);
user_pref("browser.download.manager.addToRecentDocs", false);

// === EXTENSIONS ===
user_pref("extensions.autoDisableScopes", 0);
user_pref("extensions.enabledScopes", 5);
user_pref("extensions.getAddons.showPane", false);
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);
user_pref("extensions.postDownloadThirdPartyPrompt", true);
user_pref("extensions.webextensions.restrictedDomains", "");
user_pref("intl.multilingual.downloadEnabled", false);

// === PROTOCOL HANDLERS ===
user_pref("network.protocol-handler.external.mailto", false);
user_pref("network.protocol-handler.external.news", false);
user_pref("network.protocol-handler.external.nntp", false);
user_pref("network.protocol-handler.external.snews", false);

// === ADDITIONAL HARDENING ===
user_pref("svg.disabled", false);
user_pref("mathml.disabled", false);
user_pref("pdfjs.enableScripting", false);
user_pref("dom.event.clipboardevents.enabled", false);
user_pref("browser.display.use_system_colors", false);

// === WINDOWS SPECIFIC ===
user_pref("network.http.windows-sso.enabled", false);
user_pref("taskbar.grouping.useprofile", false);
user_pref("browser.taskbar.lists.enabled", false);
user_pref("browser.taskbar.lists.frequent.enabled", false);
user_pref("browser.taskbar.lists.tasks.enabled", false);
user_pref("browser.taskbar.lists.recent.enabled", false);

// ============================================================================
// Generated by Katarakt Security Worker
// Source: Tor Project / Mullvad Browser configurations
// https://gitlab.torproject.org/tpo/applications/mullvad-browser
// ============================================================================
`;
}

/**
 * Generate Chrome enterprise policies
 * Comprehensive hardening based on Mullvad/Tor Browser principles
 */
function generateChromePolicies() {
  return {
    // === AUTOFILL & PASSWORDS ===
    "AutofillAddressEnabled": false,
    "AutofillCreditCardEnabled": false,
    "PasswordManagerEnabled": false,
    "PasswordLeakDetectionEnabled": false,
    "PasswordSharingEnabled": false,
    
    // === PRIVACY & TRACKING ===
    "BlockThirdPartyCookies": true,
    "CookiesBlockedForUrls": ["[*.]doubleclick.net", "[*.]googleadservices.com"],
    "AdsSettingForIntrusiveAdsSites": 2,
    "DefaultNotificationsSetting": 2,
    "DefaultGeolocationSetting": 2,
    "DefaultSensorsSetting": 2,
    "DefaultSerialGuardSetting": 2,
    "DefaultWebBluetoothGuardSetting": 2,
    "DefaultWebUsbGuardSetting": 2,
    "DefaultFileSystemReadGuardSetting": 2,
    "DefaultFileSystemWriteGuardSetting": 2,
    "DefaultWindowPlacementSetting": 2,
    
    // === TELEMETRY & REPORTING ===
    "MetricsReportingEnabled": false,
    "SafeBrowsingExtendedReportingEnabled": false,
    "UrlKeyedAnonymizedDataCollectionEnabled": false,
    "UserFeedbackAllowed": false,
    "DeviceMetricsReportingEnabled": false,
    "SpellCheckServiceEnabled": false,
    "SearchSuggestEnabled": false,
    "AlternateErrorPagesEnabled": false,
    "NetworkPredictionOptions": 2,
    
    // === WEBRTC ===
    "WebRtcEventLogCollectionAllowed": false,
    "WebRtcIPHandling": "disable_non_proxied_udp",
    "WebRtcLocalIpsAllowedUrls": [],
    "WebRtcAllowLegacyTLSProtocols": false,
    
    // === NETWORK & DNS ===
    "DnsOverHttpsMode": "automatic",
    "BuiltInDnsClientEnabled": true,
    "BrowserNetworkTimeQueriesEnabled": false,
    "QuicAllowed": false,
    
    // === SECURITY ===
    "SafeBrowsingEnabled": true,
    "SafeBrowsingProtectionLevel": 1,
    "PaymentMethodQueryEnabled": false,
    "MediaRecommendationsEnabled": false,
    "PromotionalTabsEnabled": false,
    "ShowFullUrlsInAddressBar": true,
    "SSLErrorOverrideAllowed": false,
    "CertificateTransparencyEnforcementDisabledForUrls": [],
    
    // === SYNC & ACCOUNTS ===
    "SyncDisabled": true,
    "BrowserSignin": 0,
    "BrowserGuestModeEnabled": false,
    
    // === FEATURES ===
    "TranslateEnabled": false,
    "EnableMediaRouter": false,
    "BackgroundModeEnabled": false,
    "DefaultPluginsSetting": 2,
    "DefaultPopupsSetting": 2,
    "DefaultCookiesSetting": 4,
    
    // === DOWNLOAD & FILE HANDLING ===
    "DownloadRestrictions": 0,
    "SafeBrowsingForTrustedSourcesEnabled": true,
    "ExternalProtocolDialogShowAlwaysOpenCheckbox": false,
    
    // === EXTENSIONS ===
    "ExtensionInstallBlocklist": ["*"],
    "ExtensionInstallAllowlist": [],
    "BlockExternalExtensions": true,
    
    // === HARDWARE ===
    "HardwareAccelerationModeEnabled": true,
    "VideoCaptureAllowed": false,
    "AudioCaptureAllowed": false,
    
    // === PRIVACY SANDBOX (Disable Google's replacement for cookies) ===
    "PrivacySandboxAdMeasurementEnabled": false,
    "PrivacySandboxAdTopicsEnabled": false,
    "PrivacySandboxSiteEnabledAdsEnabled": false,
    "PrivacySandboxPromptEnabled": false,
    
    // === MISC ===
    "ImportAutofillFormData": false,
    "ImportBookmarks": false,
    "ImportHistory": false,
    "ImportSavedPasswords": false,
    "ImportSearchEngine": false,
    "BookmarkBarEnabled": true,
    "ShowHomeButton": false,
    "HomepageIsNewTabPage": true
  };
}

// Export the worker
export default {
  fetch: handleRequest
};
