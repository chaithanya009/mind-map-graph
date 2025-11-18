// Background service worker (MV3, type=module)
// Generic AiTM (Evilginx-style) detection for Microsoft 365 - Block-only v1

const tabStateById = new Map();

let allowlistHostPatterns = [];
let heuristicsConfig = {
  minIndicatorsToBlock: 2,
  requireBrandMismatch: true
};

async function loadConfiguration() {
  try {
    const allowlistUrl = chrome.runtime.getURL('config/allowlist.json');
    const heuristicsUrl = chrome.runtime.getURL('config/heuristics.json');
    const [allowlistResp, heuristicsResp] = await Promise.allSettled([
      fetch(allowlistUrl),
      fetch(heuristicsUrl)
    ]);
    if (allowlistResp.status === 'fulfilled' && allowlistResp.value.ok) {
      allowlistHostPatterns = await allowlistResp.value.json();
    }
    if (heuristicsResp.status === 'fulfilled' && heuristicsResp.value.ok) {
      const cfg = await heuristicsResp.value.json();
      heuristicsConfig = { ...heuristicsConfig, ...cfg };
    }
  } catch (err) {
    // Keep defaults on error
    console.warn('Configuration load failed, using defaults', err);
  }
}

function getHostnameFromUrl(urlString) {
  try {
    const u = new URL(urlString);
    return u.hostname.toLowerCase();
  } catch {
    return '';
  }
}

function normalizeHeaderName(name) {
  return String(name || '').toLowerCase();
}

function matchHostnamePattern(hostname, pattern) {
  // Supports exact host and wildcard prefix like *.office.com
  const hn = String(hostname || '').toLowerCase();
  const pat = String(pattern || '').toLowerCase();
  if (!hn || !pat) return false;
  if (pat.startsWith('*.')) {
    const suffix = pat.slice(1); // ".office.com"
    return hn === pat.slice(2) || hn.endsWith(suffix);
  }
  return hn === pat;
}

function isHostnameAllowlisted(hostname) {
  return allowlistHostPatterns.some((p) => matchHostnamePattern(hostname, p));
}

function ensureTabState(tabId) {
  if (!tabStateById.has(tabId)) {
    tabStateById.set(tabId, {
      url: '',
      hostname: '',
      indicators: new Set(),
      indicatorDetails: []
    });
  }
  return tabStateById.get(tabId);
}

function addIndicators(tabId, indicators, details = []) {
  const state = ensureTabState(tabId);
  for (const i of indicators) state.indicators.add(i);
  for (const d of details) state.indicatorDetails.push(d);
  maybeBlock(tabId);
}

function collectDecision(state) {
  const indicators = Array.from(state.indicators);
  const brandMismatch = indicators.includes('brand_mismatch');
  if (heuristicsConfig.requireBrandMismatch && !brandMismatch) {
    return { shouldBlock: false, indicators };
  }
  const independent = brandMismatch ? indicators.filter((i) => i !== 'brand_mismatch') : indicators;
  const minNeeded = Math.max(heuristicsConfig.minIndicatorsToBlock - (brandMismatch ? 1 : 0), 0);
  const shouldBlock = brandMismatch && independent.length >= minNeeded && independent.length >= 1;
  return { shouldBlock, indicators };
}

async function blockTab(tabId, originalUrl) {
  const state = ensureTabState(tabId);
  const reasons = encodeURIComponent(JSON.stringify(Array.from(state.indicators)));
  const domain = encodeURIComponent(state.hostname || getHostnameFromUrl(originalUrl));
  const src = encodeURIComponent(originalUrl || '');
  const blockUrl = chrome.runtime.getURL(`block/block.html?domain=${domain}&reasons=${reasons}&src=${src}`);
  try {
    await chrome.tabs.update(tabId, { url: blockUrl });
  } catch (err) {
    console.warn('Failed to update tab to block page', err);
  }
}

function maybeBlock(tabId) {
  const state = ensureTabState(tabId);
  const { shouldBlock } = collectDecision(state);
  if (shouldBlock) {
    blockTab(tabId, state.url);
  }
}

// URL/OIDC path heuristics (non-MS domain)
function urlHeuristics(urlString, hostname) {
  const indicators = [];
  const details = [];
  const isMsHost = isHostnameAllowlisted(hostname);
  if (isMsHost) return { indicators, details };
  if (!heuristicsConfig?.url?.enableOidcPattern) return { indicators, details };
  let u;
  try {
    u = new URL(urlString);
  } catch {
    return { indicators, details };
  }
  const path = (u.pathname || '').toLowerCase();
  const search = u.searchParams;
  const hasAuthorizePath = path.includes('/oauth2/v2.0/authorize') || path.includes('/common/oauth2/') || path.includes('/oauth2/authorize');
  const trioParams = search.has('client_id') && search.has('redirect_uri') && (search.has('response_type') || search.has('response_mode'));
  const kmsiPath = path.includes('/kmsi') || path.includes('kmsi') || path.includes('keepmeloggedin');
  if (hasAuthorizePath || trioParams || kmsiPath) {
    indicators.push('url_m365_oidc_pattern');
    details.push({ type: 'url', reason: 'oidc_pattern', url: urlString });
  }
  return { indicators, details };
}

// Response headers heuristics (non-MS domain, main_frame)
function headerHeuristics(responseHeaders = [], hostname) {
  const indicators = [];
  const details = [];
  const isMsHost = isHostnameAllowlisted(hostname);
  if (isMsHost) return { indicators, details };
  const hdrCfg = heuristicsConfig?.headers || {};
  const headers = {};
  for (const h of responseHeaders) {
    const name = normalizeHeaderName(h.name);
    const value = String(h.value || '');
    headers[name] = value;
    if (name === 'set-cookie' && hdrCfg.enableAadCookieCheck) {
      const cookieVal = value.toLowerCase();
      if (cookieVal.includes('estsauth') || cookieVal.includes('estsauthlight') || cookieVal.includes('estsauthtoken') || cookieVal.includes('estsessionstate')) {
        indicators.push('aad_cookie_on_non_ms_domain');
        details.push({ type: 'cookie', reason: 'aad_cookie', sample: value.slice(0, 120) });
      }
    }
  }
  const hasMsHeaders = hdrCfg.enableMsHeadersCheck && (Object.keys(headers).some((k) => k.startsWith('x-ms-')) || headers['x-azure-ref'] || headers['x-ms-estes-server'] || headers['x-ms-ests-server']);
  if (hasMsHeaders) {
    indicators.push('ms_headers_on_non_ms_origin');
    details.push({ type: 'header', reason: 'ms_headers' });
  }
  const csp = headers['content-security-policy'] || '';
  if (hdrCfg.enableCspMsRefsCheck && csp && /login\.microsoftonline\.com|aadcdn\.microsoftonline-p\.com/i.test(csp)) {
    indicators.push('csp_references_ms_on_non_ms_origin');
    details.push({ type: 'csp', reason: 'ms_refs_in_csp' });
  }
  return { indicators, details };
}

// DOM signal -> brand mismatch (requires non-MS domain)
function computeBrandMismatch(domSignals, hostname) {
  const isMsHost = isHostnameAllowlisted(hostname);
  if (!isMsHost && domSignals && domSignals.m365LoginDetected) {
    return { indicators: ['brand_mismatch'], details: [{ type: 'dom', reason: 'm365_ui_on_non_ms_domain' }] };
  }
  return { indicators: [], details: [] };
}

// Navigation lifecycle: reset state on top-level commits
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const { tabId, url } = details;
  const hostname = getHostnameFromUrl(url);
  const state = ensureTabState(tabId);
  state.url = url;
  state.hostname = hostname;
  state.indicators = new Set();
  state.indicatorDetails = [];
  // URL heuristics on commit
  const urlSig = urlHeuristics(url, hostname);
  addIndicators(tabId, urlSig.indicators, urlSig.details);
});

// Observe response headers for main_frame
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type !== 'main_frame' || details.frameId !== 0) return;
    const hostname = getHostnameFromUrl(details.url);
    const headerSig = headerHeuristics(details.responseHeaders || [], hostname);
    addIndicators(details.tabId, headerSig.indicators, headerSig.details);
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders', 'extraHeaders']
);

// Receive DOM signals from content script
chrome.runtime.onMessage.addListener((message, sender) => {
  try {
    if (!sender.tab || sender.frameId !== 0) return;
    if (message && message.type === 'domSignals') {
      const tabId = sender.tab.id;
      const state = ensureTabState(tabId);
      const brand = computeBrandMismatch(message.payload, state.hostname);
      addIndicators(tabId, brand.indicators, brand.details);
    }
  } catch (err) {
    console.warn('onMessage error', err);
  }
});

// Cleanup when tab is removed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabStateById.delete(tabId);
});

// Initialize configuration at startup
loadConfiguration();


