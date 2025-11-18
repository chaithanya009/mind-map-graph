import {
  SignalObservation,
  mergeSignalCollections,
  isMicrosoftHost
} from "../lib/aitmSignals.js";
import "./blocker.js";

type SeverityRank = Record<SignalObservation["severity"], number>;

const SEVERITY_RANK: SeverityRank = {
  low: 1,
  medium: 2,
  high: 3
};

const PERSISTENT_SIGNALS = new Map<string, SignalObservation>();

const SENSITIVE_STORAGE_KEYS = [
  /^estsauth/i,
  /^ests-cookie/i,
  /^adal\./i,
  /^msal\./i,
  /^signinstatemgr/i,
  /^wpj\./i
];

let rescanTimer: number | null = null;

instrumentStorage();
observeFormSubmissions();

scheduleInitialScan();

function scheduleInitialScan() {
  if (document.readyState === "complete" || document.readyState === "interactive") {
    void runScan();
  } else {
    window.addEventListener("DOMContentLoaded", () => {
      void runScan();
    });
  }
}

function scheduleRecurringScan() {
  if (rescanTimer !== null) {
    window.clearInterval(rescanTimer);
  }
  rescanTimer = window.setInterval(() => {
    void runScan();
  }, 5000);
}

async function runScan() {
  const signals = await collectSignals();
  await chrome.runtime.sendMessage({
    type: "aitm:observations",
    payload: {
      source: "content" as const,
      signals,
      reset: true
    }
  });
  scheduleRecurringScan();
}

async function collectSignals(): Promise<SignalObservation[]> {
  const host = location.hostname;

  if (!isLikelyMicrosoftLogin()) {
    return Array.from(PERSISTENT_SIGNALS.values());
  }

  const signals: SignalObservation[] = [];
  signals.push(...detectOriginPatterns(host));
  signals.push(...detectResourceAnomalies(host));
  signals.push(...detectStoredSecrets(host));
  signals.push(...detectCspAnomalies(host));
  signals.push(...detectIframeAnomalies(host));
  signals.push(...(await detectServiceWorkerAnomalies(host)));

  const merged = mergeSignalCollections(signals, Array.from(PERSISTENT_SIGNALS.values()));
  merged.forEach((signal) => upsertPersistentSignal(signal));
  return merged;
}

function detectOriginPatterns(host: string): SignalObservation[] {
  const findings: SignalObservation[] = [];
  const microsoftActions = getMicrosoftFormActions();

  if (!isMicrosoftHost(host) && microsoftActions.length > 0) {
    findings.push({
      id: "content:origin-bridge",
      severity: "high",
      description:
        "Microsoft sign-in form actions are embedded on a non-Microsoft origin.",
      evidence: {
        host,
        actions: microsoftActions
      }
    });
  }

  if (isMicrosoftHost(host)) {
    const externalActions = getExternalFormActions();
    if (externalActions.length > 0) {
      findings.push({
        id: "content:form-action-external",
        severity: "high",
        description:
          "Sign-in forms submit credentials to a non-Microsoft domain.",
        evidence: {
          host,
          actions: externalActions
        }
      });
    }
  }

  return findings;
}

function detectResourceAnomalies(host: string): SignalObservation[] {
  if (isMicrosoftHost(host)) {
    return [];
  }

  const suspiciousResources = Array.from(
    document.querySelectorAll<HTMLScriptElement | HTMLLinkElement | HTMLImageElement>(
      "script[src*='login.microsoftonline.com'],script[src*='aadcdn.msauth.net'],link[href*='login.microsoftonline.com'],img[src*='login.microsoftonline.com']"
    )
  ).map((node) => node.getAttribute("src") ?? node.getAttribute("href"))
    .filter((value): value is string => Boolean(value));

  if (suspiciousResources.length === 0) {
    return [];
  }

  return [
    {
      id: "content:resource-bridging",
      severity: "medium",
      description:
        "Microsoft authentication assets are being loaded while the page is served from a different origin.",
      evidence: {
        host,
        resources: suspiciousResources.slice(0, 5)
      }
    }
  ];
}

function detectStoredSecrets(host: string): SignalObservation[] {
  const findings: SignalObservation[] = [];

  if (!isMicrosoftHost(host)) {
    const storageHits = collectStorageKeys();
    if (storageHits.length > 0) {
      findings.push({
        id: "content:token-storage",
        severity: "medium",
        description:
          "Sensitive Microsoft authentication artifacts are stored in web storage on a non-Microsoft origin.",
        evidence: {
          host,
          keys: storageHits
        }
      });
    }
  }

  const cookieHits = collectCookieTokens();
  if (!isMicrosoftHost(host) && cookieHits.length > 0) {
    findings.push({
      id: "content:token-cookie",
      severity: "medium",
      description:
        "Cookies resembling Microsoft session tokens are present on a non-Microsoft origin.",
      evidence: {
        host,
        cookies: cookieHits
      }
    });
  }

  return findings;
}

function detectCspAnomalies(host: string): SignalObservation[] {
  if (isMicrosoftHost(host)) {
    return [];
  }

  const meta = document.querySelector<HTMLMetaElement>(
    "meta[http-equiv='Content-Security-Policy']"
  );

  if (!meta) {
    return [
      {
        id: "content:csp-missing",
        severity: "medium",
        description:
          "Microsoft sign-in experience is delivered without a Content Security Policy on a non-Microsoft host.",
        evidence: { host }
      }
    ];
  }

  const content = meta.content || "";
  if (content.includes("'unsafe-inline'") || /\bscript-src\b[^;]*\*/.test(content)) {
    return [
      {
        id: "content:csp-relaxed",
        severity: "low",
        description:
          "Content Security Policy allows inline scripts or wildcards, increasing interception risk.",
        evidence: {
          host,
          policy: content
        }
      }
    ];
  }

  return [];
}

function detectIframeAnomalies(host: string): SignalObservation[] {
  if (isMicrosoftHost(host)) {
    return [];
  }

  const loginIframes = Array.from(
    document.querySelectorAll<HTMLIFrameElement>("iframe[src*='login.microsoftonline.com']")
  ).map((frame) => frame.src);

  if (loginIframes.length === 0) {
    return [];
  }

  return [
    {
      id: "content:iframe-bridge",
      severity: "medium",
      description:
        "Microsoft authentication iframes are embedded within a non-Microsoft host.",
      evidence: {
        host,
        frames: loginIframes
      }
    }
  ];
}

async function detectServiceWorkerAnomalies(host: string): Promise<SignalObservation[]> {
  if (!("serviceWorker" in navigator)) {
    return [];
  }

  try {
    const registrations = await navigator.serviceWorker.getRegistrations();
    const rogue = registrations
      .map((registration) => registration.scope)
      .filter((scope): scope is string => Boolean(scope))
      .filter((scope) => {
        try {
          const scopeHost = new URL(scope).hostname;
          return !isMicrosoftHost(scopeHost);
        } catch {
          return false;
        }
      });

    if (!isMicrosoftHost(host) && rogue.length > 0) {
      return [
        {
          id: "content:service-worker-rogue",
          severity: "medium",
          description:
            "Service workers are registered for Microsoft sign-in content on a non-Microsoft domain.",
          evidence: {
            host,
            scopes: rogue
          }
        }
      ];
    }
  } catch {
    // Ignore service worker errors.
  }

  return [];
}

function isLikelyMicrosoftLogin(): boolean {
  if (document.querySelector("input[name='loginfmt']")) {
    return true;
  }
  if (document.querySelector("form[action*='login.microsoftonline.com']")) {
    return true;
  }
  if (document.title.toLowerCase().includes("sign in to your account")) {
    return true;
  }
  if (document.querySelector("[data-test-id='aadTile']")) {
    return true;
  }
  return false;
}

function getMicrosoftFormActions(): string[] {
  return Array.from(document.forms)
    .map((form) => form.getAttribute("action") ?? "")
    .filter((action) => {
      if (!action) {
        return false;
      }
      try {
        const host = new URL(action, location.href).hostname;
        return isMicrosoftHost(host);
      } catch {
        return false;
      }
    });
}

function getExternalFormActions(): string[] {
  return Array.from(document.forms)
    .map((form) => form.getAttribute("action") ?? "")
    .filter((action) => {
      if (!action) {
        return false;
      }
      try {
        const host = new URL(action, location.href).hostname;
        return !isMicrosoftHost(host);
      } catch {
        return false;
      }
    });
}

function collectStorageKeys(): string[] {
  const keys = new Set<string>();
  try {
    for (let i = 0; i < localStorage.length; i += 1) {
      const key = localStorage.key(i);
      if (key && isSensitiveStorageKey(key)) {
        keys.add(`local:${key}`);
      }
    }
  } catch {
    // Ignore access issues.
  }

  try {
    for (let i = 0; i < sessionStorage.length; i += 1) {
      const key = sessionStorage.key(i);
      if (key && isSensitiveStorageKey(key)) {
        keys.add(`session:${key}`);
      }
    }
  } catch {
    // Ignore access issues.
  }

  return Array.from(keys);
}

function collectCookieTokens(): string[] {
  try {
    return document.cookie
      .split(";")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0)
      .filter((entry) => {
        const [name] = entry.split("=", 1);
        return isSensitiveStorageKey(name);
      })
      .slice(0, 10);
  } catch {
    return [];
  }
}

function isSensitiveStorageKey(key: string): boolean {
  return SENSITIVE_STORAGE_KEYS.some((pattern) => pattern.test(key));
}

function upsertPersistentSignal(signal: SignalObservation) {
  const existing = PERSISTENT_SIGNALS.get(signal.id);
  if (!existing) {
    PERSISTENT_SIGNALS.set(signal.id, signal);
    return;
  }
  if (SEVERITY_RANK[signal.severity] > SEVERITY_RANK[existing.severity]) {
    PERSISTENT_SIGNALS.set(signal.id, signal);
  } else if (SEVERITY_RANK[signal.severity] === SEVERITY_RANK[existing.severity]) {
    PERSISTENT_SIGNALS.set(signal.id, {
      ...existing,
      evidence: {
        ...existing.evidence,
        ...signal.evidence
      }
    });
  }
}

function instrumentStorage() {
  const originalSetItem = Storage.prototype.setItem;
  const originalRemoveItem = Storage.prototype.removeItem;

  Storage.prototype.setItem = function patchedSetItem(key: string, value: string) {
    if (!isMicrosoftHost(location.hostname) && isSensitiveStorageKey(key)) {
      upsertPersistentSignal({
        id: "content:storage-hook",
        severity: "medium",
        description:
          "Sensitive Microsoft key stored via Storage API on a non-Microsoft origin.",
        evidence: {
          key,
          valuePreview: value.slice(0, 16)
        }
      });
    }
    return originalSetItem.call(this, key, value);
  };

  Storage.prototype.removeItem = function patchedRemoveItem(key: string) {
    if (!isMicrosoftHost(location.hostname) && isSensitiveStorageKey(key)) {
      upsertPersistentSignal({
        id: "content:storage-removal",
        severity: "low",
        description:
          "Sensitive Microsoft key removed from Storage API, indicating token handling.",
        evidence: { key }
      });
    }
    return originalRemoveItem.call(this, key);
  };
}

function observeFormSubmissions() {
  document.addEventListener(
    "submit",
    (event) => {
      const form = event.target as HTMLFormElement | null;
      if (!form) {
        return;
      }
      const action = form.getAttribute("action") ?? "";
      if (!action) {
        return;
      }
      try {
        const actionHost = new URL(action, location.href).hostname;
        if (!isMicrosoftHost(actionHost)) {
          upsertPersistentSignal({
            id: "content:submit-external",
            severity: "high",
            description:
              "Credential submission attempted to a non-Microsoft endpoint.",
            evidence: {
              action,
              host: actionHost
            }
          });
        }
      } catch {
        // Ignore malformed URLs.
      }
    },
    { capture: true }
  );
}

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "aitm:rescan") {
    runScan().catch((error) => console.error("Rescan failed", error));
  }
});

