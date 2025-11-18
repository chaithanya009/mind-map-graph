import { DEFAULT_SETTINGS } from "./config.js";
const SETTINGS_KEY = "settings";
const DETECTION_LOG_KEY = "detectionLog";
export async function getSettings() {
    return new Promise((resolve) => {
        chrome.storage.local.get([SETTINGS_KEY], (result) => {
            const stored = result[SETTINGS_KEY];
            resolve({ ...DEFAULT_SETTINGS, ...stored });
        });
    });
}
export async function setSettings(settings) {
    return new Promise((resolve) => {
        chrome.storage.local.set({ [SETTINGS_KEY]: settings }, () => resolve());
    });
}
export async function appendDetectionLog(entry) {
    return new Promise((resolve) => {
        chrome.storage.local.get([DETECTION_LOG_KEY], (result) => {
            const current = result[DETECTION_LOG_KEY] ?? [];
            const updated = [entry, ...current].slice(0, 50);
            chrome.storage.local.set({ [DETECTION_LOG_KEY]: updated }, () => resolve());
        });
    });
}
export async function getDetectionLog() {
    return new Promise((resolve) => {
        chrome.storage.local.get([DETECTION_LOG_KEY], (result) => {
            resolve(result[DETECTION_LOG_KEY] ?? []);
        });
    });
}
//# sourceMappingURL=storage.js.map