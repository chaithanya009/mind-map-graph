import {
  DEFAULT_THRESHOLD,
  DetectionResult,
  SignalObservation,
  evaluateSignals,
  mergeSignalCollections,
  isMicrosoftHost
} from "./lib/aitmSignals.js";

type SignalSource = "content" | "network";

type ObservationsMessage = {
  type: "aitm:observations";
  payload: {
    source: SignalSource;
    signals: SignalObservation[];
    reset?: boolean;
  };
};

type RuntimeMessage = ObservationsMessage | { type: "aitm:clear" };

interface TabSignalState {
  content: SignalObservation[];
  network: SignalObservation[];
}

interface CertificateInfo {
  subject?: string;
  issuer?: string;
  fingerprint?: {
    sha256?: string;
  };
}

interface SecurityInfo {
  certificateChain?: CertificateInfo[];
}

const tabSignals = new Map<number, TabSignalState>();
const blockedTabs = new Map<number, DetectionResult>();

chrome.runtime.onInstalled.addListener(() => {
  console.info("M365 AiTM Guard installed");
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabSignals.delete(tabId);
  blockedTabs.delete(tabId);
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) {
    resetTab(details.tabId);
  }
});

chrome.runtime.onMessage.addListener(
  (message: RuntimeMessage, sender, sendResponse) => {
    const tabId = sender.tab?.id;
    if (!tabId) {
      return;
    }

    if (message.type === "aitm:clear") {
      resetTab(tabId);
      sendResponse({ ok: true });
      return;
    }

    const { source, signals, reset } = message.payload;
    updateSignals(tabId, source, signals, Boolean(reset));
    const result = evaluateTab(tabId);
    if (result?.triggered) {
      blockedTabs.set(tabId, result);
      blockTab(tabId, result).then(() => sendResponse({ ok: true }));
      return true;
    }

    if (!result?.triggered) {
      maybeClearBlock(tabId);
    }

    sendResponse({ ok: true });
    return undefined;
  }
);

const REQUEST_FILTER = {
  urls: [
    "https://login.microsoftonline.com/*",
    "https://login.windows.net/*",
    "https://*.microsoftonline.com/*",
    "https://*.microsoft.com/*"
  ]
};

const PROXY_HEADER_NAMES = new Set([
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-original-url",
  "x-real-ip",
  "via"
]);

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details): chrome.webRequest.BlockingResponse | undefined => {
    if (details.tabId < 0) {
      return undefined;
    }

    const signals: SignalObservation[] = [];
    const requestHost = new URL(details.url).hostname;

    if (details.initiator) {
      try {
        const initiatorHost = new URL(details.initiator).hostname;
        if (!isMicrosoftHost(initiatorHost) && isMicrosoftHost(requestHost)) {
          signals.push({
            id: "network:initiator-mismatch",
            severity: "high",
            description:
              "Microsoft login resources are being requested from a non-Microsoft origin.",
            evidence: {
              initiator: initiatorHost,
              target: requestHost
            }
          });
        }
      } catch (error) {
        console.warn("Failed to parse initiator host", error);
      }
    }

    const headerHits =
      details.requestHeaders?.filter((header) =>
        PROXY_HEADER_NAMES.has(header.name.toLowerCase())
      ) ?? [];

    if (headerHits.length > 0) {
      signals.push({
        id: "network:proxy-header",
        severity: "medium",
        description:
          "Requests to Microsoft login endpoints include proxy-related headers.",
        evidence: {
          headers: headerHits.map((header) => header.name)
        }
      });
    }

    if (signals.length > 0) {
      updateSignals(details.tabId, "network", signals, false);
      const result = evaluateTab(details.tabId);
      if (result?.triggered) {
        blockedTabs.set(details.tabId, result);
        void blockTab(details.tabId, result);
      }
    }
    return undefined;
  },
  REQUEST_FILTER,
  ["requestHeaders", "extraHeaders"]
);

chrome.webRequest.onHeadersReceived.addListener(
  (details): chrome.webRequest.BlockingResponse | undefined => {
    if (details.tabId < 0) {
      return undefined;
    }

    getSecurityInfo(details.requestId)
      .then((info) => {
        if (!info) {
          return;
        }

        const certificate = info.certificateChain?.[0];
        const requestHost = new URL(details.url).hostname;

        if (
          isMicrosoftHost(requestHost) &&
          certificate &&
          !isLikelyMicrosoftCertificate(certificate)
        ) {
          const signal: SignalObservation = {
            id: "network:tls-mismatch",
            severity: "high",
            description:
              "TLS certificate for Microsoft login endpoint does not match expected issuers.",
            evidence: {
              issuer: certificate.issuer ?? null,
              subject: certificate.subject ?? null,
              fingerprint: certificate.fingerprint?.sha256 ?? null
            }
          };
          updateSignals(details.tabId, "network", [signal], false);
          const result = evaluateTab(details.tabId);
          if (result?.triggered) {
            blockedTabs.set(details.tabId, result);
            void blockTab(details.tabId, result);
          }
        }
      })
      .catch(() => {
        // Ignore failures; getSecurityInfo may not be available for all requests.
      });
    return undefined;
  },
  REQUEST_FILTER,
  ["extraHeaders"]
);

function updateSignals(
  tabId: number,
  source: SignalSource,
  signals: SignalObservation[],
  reset: boolean
) {
  const state = tabSignals.get(tabId) ?? { content: [], network: [] };
  if (reset) {
    state[source] = [];
  }
  state[source] = mergeSignalCollections(state[source], signals);
  tabSignals.set(tabId, state);
}

function evaluateTab(tabId: number): DetectionResult | undefined {
  const state = tabSignals.get(tabId);
  if (!state) {
    return undefined;
  }

  const combined = mergeSignalCollections(state.content, state.network);
  if (combined.length === 0) {
    return undefined;
  }

  return evaluateSignals(combined, { threshold: DEFAULT_THRESHOLD });
}

async function blockTab(tabId: number, result: DetectionResult) {
  try {
    await persistDetection(result);
    await chrome.tabs.sendMessage(tabId, {
      type: "aitm:block",
      payload: result
    });
  } catch (error) {
    console.warn("Unable to signal content script for blocking", error);
  }
}

function maybeClearBlock(tabId: number) {
  if (!blockedTabs.has(tabId)) {
    return;
  }
  blockedTabs.delete(tabId);
  void chrome.tabs.sendMessage(tabId, { type: "aitm:clear" }).catch(() => {
    // Content script may not be ready; ignore.
  });
}

function resetTab(tabId: number) {
  tabSignals.delete(tabId);
  maybeClearBlock(tabId);
}

const TRUSTED_ISSUERS = [
  "DigiCert TLS Hybrid ECC SHA384 2020 CA1",
  "DigiCert TLS Hybrid RSA SHA256 2020 CA1",
  "Microsoft Azure TLS Issuing CA 06",
  "Microsoft IT TLS CA 5",
  "Microsoft IT TLS SHA2"
];

function getSecurityInfo(requestId: string): Promise<SecurityInfo | undefined> {
  const webRequest = chrome.webRequest as unknown as {
    getSecurityInfo?: (
      requestId: string,
      options: { certificateChain?: boolean },
      callback: (info: SecurityInfo) => void
    ) => void;
  };

  if (typeof webRequest.getSecurityInfo !== "function") {
    return Promise.resolve(undefined);
  }

  return new Promise((resolve) => {
    webRequest.getSecurityInfo!(
      requestId,
      { certificateChain: true },
      (info: SecurityInfo) => {
        if (chrome.runtime.lastError) {
          resolve(undefined);
        } else {
          resolve(info);
        }
      }
    );
  });
}

function isLikelyMicrosoftCertificate(certificate: CertificateInfo) {
  if (!certificate) {
    return false;
  }
  if (certificate.subject?.includes("Microsoft Corporation")) {
    return true;
  }
  if (certificate.subject?.includes("login.microsoftonline.com")) {
    return true;
  }
  const issuer = certificate.issuer ?? "";
  if (issuer && TRUSTED_ISSUERS.some((trusted) => issuer.includes(trusted))) {
    return true;
  }
  return false;
}

async function persistDetection(result: DetectionResult) {
  try {
    const key = "aitmEvents";
    const store = await chrome.storage.session.get(key);
    const events: Array<Record<string, unknown>> = Array.isArray(store[key])
      ? (store[key] as Array<Record<string, unknown>>)
      : [];
    const entry = {
      timestamp: Date.now(),
      score: result.score,
      threshold: result.threshold,
      signals: result.signals.map((signal) => ({
        id: signal.id,
        severity: signal.severity,
        description: signal.description
      }))
    };
    const next = [...events, entry].slice(-50);
    await chrome.storage.session.set({ [key]: next });
  } catch (error) {
    console.warn("Failed to persist AiTM detection event", error);
  }
}

