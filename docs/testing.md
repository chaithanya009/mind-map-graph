# Manual Test Plan: M365 AiTM Guard Extension

## Prerequisites
- Chrome/Edge browser in developer mode.
- Build assets via `npm install && npm run build` inside the `extension` directory.
- Load the unpacked extension from the `extension` folder.

## Test Scenarios

1. **Baseline Microsoft login**
   - Navigate to `https://login.microsoftonline.com/`.
   - Expectation: No block page. Console should show “AiTM detection skipped: trusted Microsoft host”.

2. **Benign third-party domain**
   - Visit random HTTPS sites (e.g., `https://example.com`).
   - Expectation: No detection triggered, no block page.

3. **Simulated AiTM proxy using static capture**
   - Host a saved Microsoft login HTML on a non-Microsoft domain (e.g., via `http://localhost:8080/login/index.html`).
   - Ensure the content includes original Microsoft form actions and CDN links.
   - Expectation: Extension blocks the page, block interstitial displays signals for host anomaly, UI fingerprint, and inline upstream reference.

4. **Reverse proxy via Evilginx lab**
   - Deploy Evilginx in a controlled lab environment proxying Microsoft 365 login.
   - Browse to the Evilginx phishing domain.
   - Expectation: Block action triggers. Check detection log via `chrome.storage.local` to confirm entry recorded.

5. **Allowlist override**
   - Manually add a test domain to `ignoredHosts` using `chrome.storage.local`.
   - Reload the test site used in scenario 3.
   - Expectation: Page loads without blocking; detection log should not gain a new record.

6. **Blocked page UX**
   - When block occurs, verify:
     - Score, threshold, and host fields are populated.
     - Signals list enumerates at least three entries.
     - “Close tab” button closes the tab.

7. **Persistence check**
   - Trigger detection, close the blocked tab.
   - Reopen a normal tab and call `chrome.runtime.sendMessage({ type: 'get-detection-log' })` from DevTools.
   - Expectation: Latest detection appears first with timestamps.

