import { DEFAULT_SETTINGS, DetectionSettings } from "./config.js";

const SETTINGS_KEY = "settings";
const DETECTION_LOG_KEY = "detectionLog";

export async function getSettings(): Promise<DetectionSettings> {
  return new Promise((resolve) => {
    chrome.storage.local.get([SETTINGS_KEY], (result) => {
      const stored = result[SETTINGS_KEY] as Partial<DetectionSettings> | undefined;
      resolve({ ...DEFAULT_SETTINGS, ...stored });
    });
  });
}

export async function setSettings(settings: DetectionSettings): Promise<void> {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [SETTINGS_KEY]: settings }, () => resolve());
  });
}

export interface DetectionLogEntry {
  url: string;
  host: string;
  score: number;
  threshold: number;
  detectedAt: number;
  signals: Array<{ id: string; description: string }>;
}

export async function appendDetectionLog(entry: DetectionLogEntry): Promise<void> {
  return new Promise((resolve) => {
    chrome.storage.local.get([DETECTION_LOG_KEY], (result) => {
      const current = (result[DETECTION_LOG_KEY] as DetectionLogEntry[]) ?? [];
      const updated = [entry, ...current].slice(0, 50);
      chrome.storage.local.set({ [DETECTION_LOG_KEY]: updated }, () => resolve());
    });
  });
}

export async function getDetectionLog(): Promise<DetectionLogEntry[]> {
  return new Promise((resolve) => {
    chrome.storage.local.get([DETECTION_LOG_KEY], (result) => {
      resolve((result[DETECTION_LOG_KEY] as DetectionLogEntry[]) ?? []);
    });
  });
}

