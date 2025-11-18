import { appendDetectionLog, getDetectionLog, getSettings, setSettings } from "./storage.js";
const DETECTION_STORAGE_KEY = "latestDetection";
chrome.runtime.onMessage.addListener((message, sender) => {
    if (message?.type !== "aitm-detected") {
        return;
    }
    const tabId = sender.tab?.id;
    if (tabId === undefined) {
        return;
    }
    const detectionRecord = {
        [DETECTION_STORAGE_KEY]: {
            ...message.payload,
            detectedAt: Date.now()
        }
    };
    chrome.storage.session.set(detectionRecord);
    void appendDetectionLog({
        url: message.payload.pageUrl,
        host: message.payload.matchedHost,
        score: message.payload.score,
        threshold: message.payload.threshold,
        detectedAt: Date.now(),
        signals: message.payload.signals
    });
    const url = new URL(chrome.runtime.getURL("blocked.html"));
    url.searchParams.set("source", encodeURIComponent(message.payload.pageUrl));
    chrome.tabs.update(tabId, { url: url.toString() }, () => {
        if (chrome.runtime.lastError) {
            console.error("Failed to redirect to block page", chrome.runtime.lastError);
        }
    });
});
chrome.runtime.onInstalled.addListener(async () => {
    const settings = await getSettings();
    await setSettings(settings);
});
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type === "get-latest-detection") {
        chrome.storage.session.get([DETECTION_STORAGE_KEY], (data) => {
            sendResponse(data[DETECTION_STORAGE_KEY] ?? null);
        });
        return true;
    }
    if (message?.type === "get-detection-log") {
        void (async () => {
            const log = await getDetectionLog();
            sendResponse(log);
        })();
        return true;
    }
    if (message?.type === "update-settings") {
        void (async () => {
            await setSettings(message.payload);
            sendResponse({ success: true });
        })();
        return true;
    }
    if (message?.type === "get-settings") {
        void (async () => {
            const settings = await getSettings();
            sendResponse(settings);
        })();
        return true;
    }
    return undefined;
});
//# sourceMappingURL=background.js.map