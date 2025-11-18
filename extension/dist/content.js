import { detectAiTM } from "./detector.js";
import { MICROSOFT_ALLOWED_HOSTS } from "./config.js";
import { getSettings } from "./storage.js";
function getHostname(url) {
    try {
        return new URL(url).hostname;
    }
    catch {
        return "";
    }
}
function collectSnapshot() {
    const html = document.documentElement?.outerHTML ?? "";
    const forms = Array.from(document.forms).map((form) => ({
        action: form.getAttribute("action")
    }));
    const scriptSrcs = Array.from(document.querySelectorAll("script[src]")).map((script) => script.src);
    const linkHrefs = Array.from(document.querySelectorAll("link[href]")).map((link) => link.href);
    const markers = {
        hasAccountField: Boolean(document.querySelector("#i0116")),
        hasPasswordField: Boolean(document.querySelector("#i0118")),
        hasContinueButton: Boolean(document.querySelector("#idSIButton9"))
    };
    return {
        hostname: window.location.hostname,
        url: window.location.href,
        html,
        forms,
        scriptSrcs,
        linkHrefs,
        markers
    };
}
async function evaluatePage() {
    const settings = await getSettings();
    if (!settings.enabled) {
        return;
    }
    const snapshot = collectSnapshot();
    const result = detectAiTM(snapshot, {
        threshold: settings.scoreThreshold,
        trustedHosts: MICROSOFT_ALLOWED_HOSTS,
        ignoredHosts: settings.ignoredHosts
    });
    if (!result) {
        return;
    }
    chrome.runtime.sendMessage({
        type: "aitm-detected",
        payload: result
    });
}
void evaluatePage();
//# sourceMappingURL=content.js.map