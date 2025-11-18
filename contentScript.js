/**
 * Simple heuristic detector for Evilginx-style AitM phishing toolkits.
 * This is NOT a signature of Evilginx itself, but a behavioral approximation
 * of reverse-proxy login pages targeting common IdPs.
 */

/**
 * Retrieve settings from the background script.
 * @returns {Promise<any>}
 */
function getSettingsFromBackground() {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "GET_SETTINGS" }, (response) => {
      resolve(response && response.settings ? response.settings : {});
    });
  });
}

/**
 * Compute heuristic score and reasons for suspicion.
 * @param {string[]} idpDomains
 * @returns {{score: number, reasons: string[]}}
 */
function evaluatePageForAitM(idpDomains) {
  const reasons = [];
  let score = 0;

  try {
    const currentHost = window.location.hostname;
    const currentHref = window.location.href;

    const isTrustedIdpHost = (host) => {
      return idpDomains.some((idp) => {
        return host === idp || host.endsWith("." + idp);
      });
    };

    const thisIsTrustedIdp = isTrustedIdpHost(currentHost);

    // Heuristic 1: non-IdP domain embedding IdP login endpoints in forms or iframes
    if (!thisIsTrustedIdp) {
      const forms = Array.from(document.forms || []);
      forms.forEach((form) => {
        const action = form.getAttribute("action") || "";
        try {
          const url = new URL(action, currentHref);
          if (isTrustedIdpHost(url.hostname)) {
            score += 40;
            reasons.push(
              `Non-IdP host ${currentHost} has a form posting to IdP host ${url.hostname}.`
            );
          }
        } catch {
          // ignore invalid URLs
        }
      });

      const iframes = Array.from(document.querySelectorAll("iframe"));
      iframes.forEach((iframe) => {
        const src = iframe.getAttribute("src") || "";
        if (!src) return;
        try {
          const url = new URL(src, currentHref);
          if (isTrustedIdpHost(url.hostname)) {
            score += 30;
            reasons.push(
              `Non-IdP host ${currentHost} embeds IdP host ${url.hostname} in an iframe.`
            );
          }
        } catch {
          // ignore
        }
      });
    }

    // Heuristic 2: Suspicious localStorage keys indicating token/session handling on non-IdP host
    if (!thisIsTrustedIdp && window.localStorage) {
      const keys = Object.keys(window.localStorage);
      const suspiciousKeyPatterns = [
        "token",
        "access_token",
        "id_token",
        "refresh_token",
        "session",
        "cookies",
        "evilginx",
        "aitm"
      ];
      const suspiciousKeys = keys.filter((k) =>
        suspiciousKeyPatterns.some((pat) =>
          k.toLowerCase().includes(pat.toLowerCase())
        )
      );
      if (suspiciousKeys.length > 0) {
        score += 20;
        reasons.push(
          `Non-IdP host ${currentHost} has suspicious localStorage keys: ${suspiciousKeys.join(
            ", "
          )}.`
        );
      }
    }

    // Heuristic 3: Page title / content hints at well-known IdPs on an untrusted host
    if (!thisIsTrustedIdp) {
      const title = (document.title || "").toLowerCase();
      const idpHints = [
        "microsoft",
        "office 365",
        "office365",
        "okta",
        "google sign in",
        "sign in",
        "single sign-on",
        "sso"
      ];
      if (idpHints.some((hint) => title.includes(hint))) {
        score += 10;
        reasons.push(
          `Non-IdP host ${currentHost} has login-like title "${document.title}".`
        );
      }
    }

    // Heuristic 4: Mixed content from multiple IdP domains
    if (!thisIsTrustedIdp) {
      const allElements = Array.from(
        document.querySelectorAll("script[src], link[href], img[src]")
      );
      const referencedIdpHosts = new Set();
      allElements.forEach((el) => {
        const src = el.getAttribute("src") || el.getAttribute("href") || "";
        if (!src) return;
        try {
          const url = new URL(src, currentHref);
          if (isTrustedIdpHost(url.hostname)) {
            referencedIdpHosts.add(url.hostname);
          }
        } catch {
          // ignore
        }
      });
      if (referencedIdpHosts.size > 0) {
        score += 10;
        reasons.push(
          `Non-IdP host ${currentHost} includes resources from IdP hosts: ${Array.from(
            referencedIdpHosts
          ).join(", ")}.`
        );
      }
    }
  } catch (err) {
    // If something goes wrong, fail open but capture no score.
    console.warn("[AitM Detector] Evaluation error:", err);
  }

  return { score, reasons };
}

/**
 * Render a warn/block overlay on the page.
 * @param {"warn"|"block"} mode
 * @param {number} score
 * @param {string[]} reasons
 */
function renderInterventionOverlay(mode, score, reasons) {
  const existing = document.getElementById("aitm-detector-overlay");
  if (existing) return;

  const overlay = document.createElement("div");
  overlay.id = "aitm-detector-overlay";
  overlay.style.position = "fixed";
  overlay.style.inset = "0";
  overlay.style.backgroundColor = "rgba(0, 0, 0, 0.75)";
  overlay.style.zIndex = "2147483647";
  overlay.style.display = "flex";
  overlay.style.alignItems = "center";
  overlay.style.justifyContent = "center";
  overlay.style.fontFamily =
    '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';

  const panel = document.createElement("div");
  panel.style.maxWidth = "600px";
  panel.style.backgroundColor = "#111827";
  panel.style.borderRadius = "12px";
  panel.style.padding = "24px";
  panel.style.boxShadow = "0 20px 40px rgba(0,0,0,0.6)";
  panel.style.color = "#E5E7EB";

  const heading = document.createElement("h2");
  heading.textContent =
    mode === "block"
      ? "This page looks like a phishing toolkit (AitM) and was blocked"
      : "This page looks like a phishing toolkit (AitM)";
  heading.style.margin = "0 0 8px";
  heading.style.fontSize = "20px";
  heading.style.color = "#F97316";

  const sub = document.createElement("p");
  sub.textContent =
    "Your browser detected behavior similar to Evilginx-style adversary-in-the-middle phishing. Treat this page as untrusted.";
  sub.style.margin = "0 0 12px";
  sub.style.fontSize = "14px";
  sub.style.color = "#D1D5DB";

  const scoreP = document.createElement("p");
  scoreP.textContent = `Heuristic score: ${score}`;
  scoreP.style.margin = "0 0 8px";
  scoreP.style.fontSize = "13px";
  scoreP.style.color = "#9CA3AF";

  const reasonsList = document.createElement("ul");
  reasonsList.style.margin = "0 0 16px 18px";
  reasonsList.style.fontSize = "13px";
  reasonsList.style.color = "#D1D5DB";
  reasons.forEach((r) => {
    const li = document.createElement("li");
    li.textContent = r;
    reasonsList.appendChild(li);
  });

  const buttonRow = document.createElement("div");
  buttonRow.style.display = "flex";
  buttonRow.style.justifyContent =
    mode === "block" ? "flex-end" : "space-between";
  buttonRow.style.gap = "8px";

  if (mode === "warn") {
    const leaveBtn = document.createElement("button");
    leaveBtn.textContent = "Leave this site";
    leaveBtn.style.backgroundColor = "#DC2626";
    leaveBtn.style.color = "#F9FAFB";
    leaveBtn.style.border = "none";
    leaveBtn.style.borderRadius = "6px";
    leaveBtn.style.padding = "8px 14px";
    leaveBtn.style.cursor = "pointer";
    leaveBtn.onclick = () => {
      window.location.href = "about:blank";
    };

    const continueBtn = document.createElement("button");
    continueBtn.textContent = "Continue anyway";
    continueBtn.style.backgroundColor = "#374151";
    continueBtn.style.color = "#F9FAFB";
    continueBtn.style.border = "none";
    continueBtn.style.borderRadius = "6px";
    continueBtn.style.padding = "8px 14px";
    continueBtn.style.cursor = "pointer";
    continueBtn.onclick = () => {
      overlay.remove();
    };

    buttonRow.appendChild(leaveBtn);
    buttonRow.appendChild(continueBtn);
  } else if (mode === "block") {
    const closeBtn = document.createElement("button");
    closeBtn.textContent = "Go back";
    closeBtn.style.backgroundColor = "#DC2626";
    closeBtn.style.color = "#F9FAFB";
    closeBtn.style.border = "none";
    closeBtn.style.borderRadius = "6px";
    closeBtn.style.padding = "8px 14px";
    closeBtn.style.cursor = "pointer";
    closeBtn.onclick = () => {
      window.location.href = "about:blank";
    };
    buttonRow.appendChild(closeBtn);
  }

  panel.appendChild(heading);
  panel.appendChild(sub);
  panel.appendChild(scoreP);
  if (reasons.length > 0) {
    panel.appendChild(reasonsList);
  }
  panel.appendChild(buttonRow);
  overlay.appendChild(panel);
  document.documentElement.appendChild(overlay);
}

async function runAitMDetection() {
  const settings = await getSettingsFromBackground();
  const mode = settings.mode || "monitor";
  const idpDomains = Array.isArray(settings.idpDomains)
    ? settings.idpDomains
    : [];

  if (!idpDomains.length) {
    return;
  }

  const { score, reasons } = evaluatePageForAitM(idpDomains);

  // Simple threshold for suspicion
  const THRESHOLD = 40;
  if (score >= THRESHOLD) {
    chrome.runtime.sendMessage(
      {
        type: "AITM_DETECTED",
        pageUrl: window.location.href,
        hostname: window.location.hostname,
        score,
        reasons,
        mode
      },
      () => {
        // ignore response
      }
    );

    if (mode === "warn" || mode === "block") {
      renderInterventionOverlay(mode, score, reasons);
      if (mode === "block") {
        try {
          window.stop();
        } catch {
          // best effort
        }
      }
    }
  }
}

// Run after DOM is ready
if (document.readyState === "complete" || document.readyState === "interactive") {
  runAitMDetection();
} else {
  window.addEventListener("DOMContentLoaded", runAitMDetection, { once: true });
}


