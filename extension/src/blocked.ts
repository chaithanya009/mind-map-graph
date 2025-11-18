interface DetectionPayload {
  score: number;
  threshold: number;
  signals: Array<{ id: string; description: string }>;
  matchedHost: string;
  pageUrl: string;
  detectedAt?: number;
}

function decodeParam(value: string | null): string | null {
  if (!value) return null;
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function populateSummary(pageUrl: string | null): void {
  const summary = document.querySelector(".summary");
  if (summary && pageUrl) {
    summary.innerHTML = `
      We blocked access to <code>${pageUrl}</code> because it looks like an adversary-in-the-middle
      phishing toolkit attempting to relay the Microsoft 365 sign-in flow.
    `;
  }
}

function populateDetection(data: DetectionPayload | null): void {
  const scoreNode = document.getElementById("score");
  const thresholdNode = document.getElementById("threshold");
  const hostnameNode = document.getElementById("hostname");
  const signalList = document.getElementById("signal-list");

  if (!scoreNode || !thresholdNode || !hostnameNode || !signalList) {
    return;
  }

  if (!data) {
    scoreNode.textContent = "n/a";
    thresholdNode.textContent = "n/a";
    hostnameNode.textContent = "n/a";
    signalList.innerHTML = "<li>No detection details available.</li>";
    return;
  }

  scoreNode.textContent = `${data.score}`;
  thresholdNode.textContent = `${data.threshold}`;
  hostnameNode.textContent = data.matchedHost;

  signalList.innerHTML = "";
  data.signals.forEach((signal) => {
    const li = document.createElement("li");
    li.textContent = signal.description;
    signalList.appendChild(li);
  });
}

function wireCloseButton(): void {
  const closeButton = document.getElementById("close-tab");
  if (!closeButton) {
    return;
  }

  closeButton.addEventListener("click", () => {
    window.close();
  });
}

async function init(): Promise<void> {
  const params = new URLSearchParams(window.location.search);
  const encodedSource = params.get("source");
  const originalUrl = decodeParam(encodedSource);
  populateSummary(originalUrl);

  chrome.runtime.sendMessage(
    {
      type: "get-latest-detection"
    },
    (response: DetectionPayload | null) => {
      populateDetection(response);
    }
  );

  wireCloseButton();
}

void init();

