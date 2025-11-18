import { DetectionResult, SignalObservation } from "../lib/aitmSignals.js";

let overlayElement: HTMLDivElement | null = null;
let previousOverflow: string | null = null;

const SEVERITY_SCORE: Record<SignalObservation["severity"], number> = {
  high: 0,
  medium: 1,
  low: 2
};

export function showBlockOverlay(result: DetectionResult) {
  if (overlayElement) {
    return;
  }

  overlayElement = document.createElement("div");
  overlayElement.id = "aitm-block-overlay";
  overlayElement.setAttribute(
    "style",
    [
      "position: fixed",
      "inset: 0",
      "background: rgba(0,0,0,0.85)",
      "color: #ffffff",
      "z-index: 2147483647",
      "display: flex",
      "flex-direction: column",
      "justify-content: center",
      "align-items: center",
      "font-family: 'Segoe UI', sans-serif"
    ].join(";")
  );

  const container = document.createElement("div");
  container.setAttribute(
    "style",
    [
      "max-width: 480px",
      "margin: 0 auto",
      "padding: 32px",
      "background: rgba(22, 27, 34, 0.9)",
      "border-radius: 16px",
      "text-align: center",
      "box-shadow: 0 12px 32px rgba(0,0,0,0.4)"
    ].join(";")
  );

  const title = document.createElement("h1");
  title.textContent = "Sign-in blocked for your safety";
  title.setAttribute(
    "style",
    "margin: 0 0 16px; font-size: 24px; font-weight: 600;"
  );

  const description = document.createElement("p");
  description.textContent =
    "We detected signs of an adversary-in-the-middle phishing toolkit on this page. Access has been blocked to protect your Microsoft 365 account.";
  description.setAttribute("style", "margin: 0 0 16px; line-height: 1.5;");

  const status = document.createElement("p");
  status.textContent = `Detection score ${result.score} of ${result.threshold} required to block.`;
  status.setAttribute(
    "style",
    "margin: 0 0 16px; font-size: 14px; color: #9ca3af;"
  );

  const reasonsHeading = document.createElement("h2");
  reasonsHeading.textContent = "Why we blocked this page";
  reasonsHeading.setAttribute(
    "style",
    "margin: 0 0 12px; font-size: 18px; font-weight: 600;"
  );

  const reasonsList = document.createElement("ul");
  reasonsList.setAttribute(
    "style",
    [
      "margin: 0 0 16px",
      "padding-left: 20px",
      "text-align: left",
      "line-height: 1.5"
    ].join(";")
  );

  const sortedSignals = [...result.signals].sort((a, b) => {
    return SEVERITY_SCORE[a.severity] - SEVERITY_SCORE[b.severity];
  });

  sortedSignals.forEach((signal) => {
    const item = document.createElement("li");
    item.textContent = signal.description;
    item.setAttribute(
      "style",
      [
        "margin-bottom: 8px",
        `color: ${
          signal.severity === "high"
            ? "#fca5a5"
            : signal.severity === "medium"
            ? "#fcd34d"
            : "#e5e7eb"
        }`
      ].join(";")
    );
    reasonsList.appendChild(item);
  });

  if (sortedSignals.length === 0) {
    const fallback = document.createElement("li");
    fallback.textContent =
      "Suspicious adversary-in-the-middle behavior was detected.";
    reasonsList.appendChild(fallback);
  }

  const action = document.createElement("p");
  action.textContent =
    "Close this tab and report the suspicious link to your security team. Do not re-enter your credentials.";
  action.setAttribute("style", "margin: 0 0 8px; line-height: 1.5;");

  const hint = document.createElement("p");
  hint.textContent =
    "If you believe this is a mistake, capture a screenshot and contact support with the time and URL.";
  hint.setAttribute(
    "style",
    "margin: 0; font-size: 13px; color: #d1d5db; line-height: 1.4;"
  );

  container.appendChild(title);
  container.appendChild(description);
  container.appendChild(status);
  container.appendChild(reasonsHeading);
  container.appendChild(reasonsList);
  container.appendChild(action);
  container.appendChild(hint);
  overlayElement.appendChild(container);

  previousOverflow = document.documentElement.style.overflow || null;
  document.documentElement.style.overflow = "hidden";
  document.documentElement.appendChild(overlayElement);
}

export function removeBlockOverlay() {
  if (!overlayElement) {
    return;
  }
  overlayElement.remove();
  overlayElement = null;
  if (previousOverflow !== null) {
    document.documentElement.style.overflow = previousOverflow;
    previousOverflow = null;
  } else {
    document.documentElement.style.removeProperty("overflow");
  }
}

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "aitm:block") {
    showBlockOverlay(message.payload as DetectionResult);
  }
  if (message.type === "aitm:clear") {
    removeBlockOverlay();
  }
});

