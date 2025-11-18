# Microsoft 365 AiTM Detection Signals

## Data Available to MV3 Extension
- Browser context via content script: DOM APIs, window location, storage, CSP meta tags, injected scripts, form actions.
- Service worker via `webRequest` listeners: request/response headers, TLS info (`securityInfo` via `webRequest.getSecurityInfo`), redirect chains.
- Chrome storage: persist detection state and block decisions.

## Login Flow Landmarks
- Legitimate M365 login uses `https://login.microsoftonline.com/` pages and redirects to `https://login.microsoftonline.com/common/oauth2/` endpoints before returning to tenant-specific URLs.
- Cookies and tokens are delivered on same-origin requests protected by modern security headers (CSP, HSTS).
- Credential form submissions are confined to Microsoft-owned domains with stable TLS issuer chains (Microsoft IT TLS CA, DigiCert).

## Heuristic Signals

1. **Origin Bridging**
   - Form action or fetch/XHR targets differ from the top-level origin but still resemble Microsoft endpoints (e.g., contain `login.microsoftonline.com` yet resolved host is attacker domain).
   - Detection: Inspect form `action`, overridden `submit` handlers, and intercepted `fetch`/`XMLHttpRequest` wrappers; compare with `document.location.origin` and `URL` resolution.

2. **Proxy Header Leakage**
   - Presence of reverse-proxy headers (e.g., `x-forwarded-host`, `x-original-url`) on requests to Microsoft endpoints.
   - Detection: Service worker `webRequest.onBeforeSendHeaders`; flag when such headers are present on requests initiated from M365 pages.

3. **TLS Identity Mismatch**
   - Requests to Microsoft hostnames whose TLS certificate subject/issuer does not match expected Microsoft root chain.
   - Detection: `chrome.webRequest.getSecurityInfo` during `onHeadersReceived`; validate certificate chain against allowlist.

4. **Credential Field Cloning**
   - Credential inputs rendered in iframes sourced from attacker domains or DOM cloned into attacker-controlled container before submission.
   - Detection: Monitor for input elements with `type=password` where `ownerDocument.location.origin` differs from Microsoft domains or nodes moved to hidden forms.

5. **Session Token Extraction Scripts**
   - Scripts attempting to read cookies via `document.cookie`, intercept `localStorage` tokens, or export data through beacon/fetch to non-Microsoft domains shortly after login.
   - Detection: Content script monitors script execution for known token storage keys (e.g., `ESTSAUTH`, `MSAL`) and outbound requests.

6. **Storage Tampering Patterns**
   - Repeated writes to storage keys used by known AiTM kits (e.g., `__Secure-PS-`, `evilginx_session`) or anomalous storage operations immediately after credential submission.
   - Detection: Wrap `localStorage`/`sessionStorage` mutators and observe suspicious key patterns; keep heuristics generic (look for random GUID-like keys on non-Microsoft origins).

7. **Service Worker Hijack**
   - Registration of new service workers on Microsoft login pages originating from non-Microsoft scopes.
   - Detection: Inspect `navigator.serviceWorker.getRegistrations()` for scopes not matching Microsoft domains while on login pages.

8. **Content Security Policy Downgrade**
   - CSP headers or meta tags loosened (e.g., allowing `unsafe-inline`, wildcard origins) compared to known Microsoft CSP baselines.
   - Detection: Compare observed CSP directives against baseline snapshot; flag if wildcard/external origins permitted for scripts or connects.

9. **Prompt Timing Anomalies**
   - AiTM flows often introduce additional redirects or delays between credential input and MFA prompt.
   - Detection: Track time between form submission and navigation to expected MFA endpoints; flag excessive latency combined with other signals.

## Signal Scoring Strategy
- Assign weights to each signal; block when cumulative score exceeds threshold.
- Include debounce to avoid false positives from benign plugins by requiring at least one high-confidence signal (e.g., TLS mismatch) or multiple medium signals.

## Microsoft Domain Reference
- `login.microsoftonline.com`
- `login.windows.net`
- `aadcdn.msauth.net`
- `microsoftonline-p.com`
- `microsoft.com` and tenant-specific subdomains.

Maintain allowlists for known legitimate third-party login customizations to reduce noise.

