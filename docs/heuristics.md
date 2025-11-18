## AiTM Detection Heuristic Draft

### Target Scenario
- Focus on Microsoft 365 interactive logins that should normally occur on trusted Microsoft domains (`login.microsoftonline.com`, `login.live.com`, `microsoft.com`, `office.com`, `msauth.net`, `msftauth.net`).
- Detect adversary-in-the-middle proxy toolkits (e.g., Evilginx variants) that relay Microsoft login pages through a lookalike domain to intercept credentials and tokens.

### Signals To Collect In The Browser
1. **Host anomaly**
   - Top-level frame host is not in the trusted Microsoft domain allowlist.
2. **Microsoft login UI fingerprints**
   - Presence of key DOM selectors: `#i0116`, `#i0118`, `form[name="f1"]`, `.login-paginated-page`.
   - Presence of Microsoft-specific script globals (e.g., `window.apiConfig`, `window.REACT_SSR_METADATA`).
3. **Hardcoded Microsoft resource URLs**
   - Links or scripts referencing CDN domains such as `aadcdn.msftauth.net`, `logincdn.msauth.net`, `acctcdn.msauth.net`, while primary host is untrusted.
4. **Cross-origin form targets**
   - Forms with `action` attributes pointing to trusted Microsoft domains while rendered on an untrusted host (suggests proxy relay rather than redirect).
5. **Rewritten upstream URL markers**
   - Inline text or attributes containing full upstream URLs (e.g., `https://login.microsoftonline.com/` embedded in HTML) served from an untrusted host—common with reverse proxies that rewrite absolute URLs.

### Scoring Concept
- Assign one point per satisfied signal.
- Flag as malicious when score ≥ `3` (tunable).
- Ensure at least two independent signal classes (e.g., host anomaly + DOM fingerprint).

### Allow & Ignore Logic
- Maintain extension-managed allowlist for trusted domains (default: Microsoft list).
- Allow user-defined ignore list stored in extension storage for legitimate exceptions.
- Skip detection on private IP ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

### Block Action
- On detection threshold, send message to background service worker to immediately redirect the tab to an interstitial block page that explains the risk and offers no bypass in the MVP.

