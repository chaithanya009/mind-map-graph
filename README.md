# M365 AiTM (Evilginx‑style) Block‑Only Extension

This extension blocks Microsoft 365 adversary‑in‑the‑middle phishing toolkits (e.g., Evilginx‑style) using generic indicators. v1 supports Chrome + Edge (Manifest V3) with Block action only.

## Load for development
1. Build: no build required. The extension is plain MV3 files.
2. Chrome/Edge → Extensions → Enable developer mode → Load unpacked → select `extension/` folder.

## Test guidance
- Positive (AiTM): Point an Evilginx‑style reverse proxy at Microsoft login and browse through it. Expect a block when at least two indicators are present, one of which is brand mismatch.
  - Indicators include: URL OIDC patterns on non‑MS domain, AAD cookies in response headers, Microsoft `x-ms-*` headers on non‑MS origin, CSP referencing Microsoft on non‑MS origin.
- Negative (legit): Visit `https://login.microsoftonline.com/` and `https://www.office.com/`. No block should occur.
- Edge cases: Sovereign clouds (US/DE/CN), localized pages, KMSI dialogs.
  - If false positive occurs on a legitimate third‑party that legitimately embeds Microsoft content, confirm that the top‑level frame is not Microsoft; block occurs only when top‑level shows M365 UI and a second indicator is present.

## Packaging
- Zip the `extension/` directory contents for store submission.
  - macOS/Linux: `cd extension && zip -r ../m365-aitm-blocker-v0.1.0.zip .`
- Chrome Web Store:
  - Developer Dashboard → Create new item → Upload the ZIP
  - Required permissions: `webRequest`, `webNavigation`, `storage`, `tabs`, `scripting`; Host permissions: `<all_urls>`
- Microsoft Edge Add-ons:
  - Partner Center → Microsoft Edge Add-ons → Create new extension → Upload the ZIP
  - Same permissions/hosts as above
  
## Enterprise deployment (optional)
- Chrome (Google Admin): Admin console → Devices → Chrome → Apps & extensions → Users & browsers → Add by ID → upload ZIP or use Store item and force‑install.
- Edge (Intune/Endpoint Manager): Apps → Windows → Microsoft Edge → Extensions → add store item or ZIP, assign to groups, configure update policy.


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


