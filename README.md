# M365 AiTM Guard Extension

This project prototypes a Chrome/Edge browser extension that blocks adversary-in-the-middle (AiTM) phishing toolkits targeting Microsoft 365 sign-in flows. The extension mirrors Push Security’s behavior-based approach by detecting suspicious proxy fingerprints in the browser and enforcing a hard block.

## Features
- Manifest V3 service worker with content script heuristics.
- Generic AiTM detection scoring Microsoft login fingerprints on untrusted hosts.
- Automatic redirect to a custom interstitial block page (no bypass in v0).
- Session-scoped detection payload for UX plus persisted detection audit log in `chrome.storage.local`.
- Configurable allowlist / ignore list (via `chrome.storage.local` for now).

## Repository Layout
- `extension/manifest.json` — Extension definition and permissions.
- `extension/src/` — TypeScript sources (`content`, `background`, `detector`, `blocked`, `config`, `storage`).
- `extension/blocked.html` / `blocked.css` — Interstitial UI assets.
- `docs/heuristics.md` — Detection signal design.
- `docs/testing.md` — Manual validation scenarios.

## Development

```bash
cd extension
npm install
npm run build
```

The TypeScript compiler outputs ESM JavaScript into `extension/dist/`. Load the unpacked extension from the `extension/` folder in Chrome/Edge developer mode.

## Detection Heuristics
See `docs/heuristics.md` for the full breakdown. In summary, the content script collects DOM and resource metadata, feeding the `detectAiTM` engine which assigns points for:
- Microsoft login UI markers (`#i0116`, `#i0118`, `#idSIButton9`) on untrusted domains.
- Microsoft CDN/script URL references from non-Microsoft hosts.
- Forms that post directly to Microsoft domains while rendered on another host.
- Inline HTML strings containing upstream Microsoft URLs.

When the score meets or exceeds the configured threshold (default `3`), the tab is redirected to the block interstitial and a detection log entry is recorded.

## Telemetry & Settings
- Detection settings (`enabled`, `scoreThreshold`, `ignoredHosts`) live in `chrome.storage.local`.
- A rolling log of the most recent 50 detections is stored under the `detectionLog` key for future surfacing in UI or API hooks.

## Testing
Refer to `docs/testing.md` for detailed manual exercises, including baseline safe pages, simulated AiTM captures, Evilginx lab validation, block UI checks, and allowlist bypasses.

