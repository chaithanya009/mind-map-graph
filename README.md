## AitM Phishing Toolkit Detector (Chrome MV3 Extension)

This Chrome/Chromium extension provides a proof-of-concept implementation of browser-based detection for Evilginx-style adversary-in-the-middle (AitM) phishing toolkits. It uses heuristic rules in a content script plus a configurable policy (monitor, warn, block) similar in spirit to Push Security's browser extension.

### Features

- **Heuristic detection** of suspicious pages that appear to proxy or embed common IdP login flows (e.g., Microsoft, Google, Okta) from untrusted hosts.
- **Configurable response modes**:
  - Monitor – silently log detections.
  - Warn – show an in-page warning overlay, allow user override.
  - Block – display a blocking overlay and attempt to stop page loading.
- **Configurable IdP domains** used as detection anchors.
- **Stubbed webhook integration** for sending JSON detection events to your own backend/SIEM.

### Files

- `manifest.json` – Chrome MV3 manifest.
- `background.js` – Service worker handling settings and detection event logging/webhook.
- `contentScript.js` – Runs on all pages, evaluates heuristics, and applies monitor/warn/block behavior.
- `options.html`, `options.css`, `options.js` – Options UI to configure mode, IdP domains, webhook URL, and debug logging.

### Loading the extension (Chrome/Edge)

1. Open `chrome://extensions` (or `edge://extensions`).
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select the folder containing this project (the directory with `manifest.json`).

### Configuring

1. In the extensions list, click **Details** on this extension, then **Extension options**.
2. Choose your **Detection mode**:
   - Monitor, Warn, or Block.
3. Adjust **Identity Provider Domains** (one per line) to match your environment.
4. Optionally set a **Webhook URL** to receive detection events as JSON `POST`s.
5. Enable **debug logging** to see detection details in the DevTools console.

### Notes and limitations

- This is a **heuristic, demo-grade detector**, not a production-ready Evilginx signature. It focuses on:
  - Non-IdP domains embedding/posting to IdP hosts.
  - Suspicious localStorage keys on non-IdP domains.
  - Login-like titles and mixed IdP resources from untrusted hosts.
- False positives and false negatives are expected; refine the heuristics to match your risk tolerance and environment.


