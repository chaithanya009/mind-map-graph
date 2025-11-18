const DEFAULT_SETTINGS = {
  mode: "monitor", // "monitor" | "warn" | "block"
  idpDomains: [
    "login.microsoftonline.com",
    "login.microsoft.com",
    "accounts.google.com",
    "login.okta.com"
  ],
  webhookUrl: "",
  debug: false
};

/**
 * Get current settings from chrome.storage.sync, with defaults.
 * @returns {Promise<typeof DEFAULT_SETTINGS>}
 */
async function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(DEFAULT_SETTINGS, (items) => {
      resolve({
        ...DEFAULT_SETTINGS,
        ...items
      });
    });
  });
}

/**
 * Persist settings to chrome.storage.sync.
 * @param {Partial<typeof DEFAULT_SETTINGS>} updates
 */
async function updateSettings(updates) {
  return new Promise((resolve) => {
    chrome.storage.sync.set(updates, () => resolve());
  });
}

/**
 * Log detection events locally and optionally send to webhook.
 * @param {object} event
 */
async function handleDetectionEvent(event) {
  const settings = await getSettings();

  const enrichedEvent = {
    ...event,
    detectedAt: new Date().toISOString(),
    extensionVersion: chrome.runtime.getManifest().version
  };

  // Store a rolling log of recent events in local storage for debugging.
  chrome.storage.local.get({ detectionLog: [] }, (data) => {
    const log = data.detectionLog || [];
    log.push(enrichedEvent);
    const trimmed = log.slice(-100); // keep last 100 entries
    chrome.storage.local.set({ detectionLog: trimmed });
  });

  if (settings.debug) {
    console.log("[AitM Detector] Detection event:", enrichedEvent);
  }

  // Stubbed webhook integration
  if (settings.webhookUrl) {
    try {
      fetch(settings.webhookUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(enrichedEvent),
        // Avoid keeping the service worker alive unnecessarily
        keepalive: true
      }).catch((err) => {
        if (settings.debug) {
          console.warn("[AitM Detector] Webhook error:", err);
        }
      });
    } catch (err) {
      if (settings.debug) {
        console.warn("[AitM Detector] Webhook exception:", err);
      }
    }
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === "AITM_DETECTED") {
    const tabUrl = sender.tab && sender.tab.url ? sender.tab.url : null;
    handleDetectionEvent({
      kind: "aitm_phishing_toolkit",
      tabUrl,
      pageUrl: message.pageUrl,
      modeApplied: message.mode,
      score: message.score,
      reasons: message.reasons || [],
      hostname: message.hostname
    });
    // Fire-and-forget
    sendResponse({ ok: true });
    return true;
  }

  if (message && message.type === "GET_SETTINGS") {
    getSettings().then((settings) => {
      sendResponse({ settings });
    });
    return true;
  }

  if (message && message.type === "UPDATE_SETTINGS") {
    updateSettings(message.settings || {}).then(() => {
      sendResponse({ ok: true });
    });
    return true;
  }
});


