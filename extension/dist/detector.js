const MICROSOFT_RESOURCE_PATTERNS = [
    /login\.microsoftonline\.com/i,
    /login\.live\.com/i,
    /aadcdn\.msftauth\.net/i,
    /logincdn\.msauth\.net/i,
    /acctcdn\.msauth\.net/i,
    /microsoftonline\.com\/common/i,
    /microsoftonline-p/i
];
function isTrustedHost(host, trustedHosts) {
    const normalized = host.toLowerCase();
    return trustedHosts.some((candidate) => {
        const cand = candidate.toLowerCase();
        return (normalized === cand ||
            normalized.endsWith(`.${cand}`));
    });
}
function isIgnoredHost(host, ignoredHosts) {
    const normalized = host.toLowerCase();
    return ignoredHosts.some((candidate) => {
        const cand = candidate.toLowerCase();
        return (normalized === cand ||
            normalized.endsWith(`.${cand}`));
    });
}
function isPrivateIPAddress(host) {
    const ipv4Match = host.match(/^(?:\d{1,3}\.){3}\d{1,3}$/);
    if (!ipv4Match) {
        return false;
    }
    const parts = host.split(".").map((part) => Number(part));
    if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) {
        return false;
    }
    const [a, b] = parts;
    if (a === 10)
        return true;
    if (a === 172 && b >= 16 && b <= 31)
        return true;
    if (a === 192 && b === 168)
        return true;
    if (a === 127)
        return true;
    return false;
}
function containsMicrosoftResource(strings) {
    return strings.some((value) => MICROSOFT_RESOURCE_PATTERNS.some((pattern) => pattern.test(value)));
}
function containsMicrosoftStrings(text) {
    if (!text) {
        return false;
    }
    return MICROSOFT_RESOURCE_PATTERNS.some((pattern) => pattern.test(text));
}
function formsPostToMicrosoft(forms) {
    return forms.some((form) => {
        const action = form.action ?? "";
        return /(?:microsoft|live)\.com/i.test(action);
    });
}
function hasMicrosoftMarkers(markers) {
    const markerValues = Object.values(markers);
    return markerValues.filter(Boolean).length >= 2;
}
export function detectAiTM(snapshot, options) {
    const hostname = snapshot.hostname.toLowerCase();
    if (!hostname) {
        return null;
    }
    if (isPrivateIPAddress(hostname) || isIgnoredHost(hostname, options.ignoredHosts)) {
        return null;
    }
    if (isTrustedHost(hostname, options.trustedHosts)) {
        return null;
    }
    const signals = [
        {
            id: "host-anomaly",
            description: `Page host ${hostname} is not in the trusted Microsoft domain list.`
        }
    ];
    if (hasMicrosoftMarkers(snapshot.markers)) {
        signals.push({
            id: "ui-fingerprint",
            description: "Page contains Microsoft 365 login UI elements on an untrusted host."
        });
    }
    if (containsMicrosoftResource(snapshot.scriptSrcs) || containsMicrosoftResource(snapshot.linkHrefs)) {
        signals.push({
            id: "cdn-leak",
            description: "Page loads Microsoft authentication CDN resources from an untrusted host."
        });
    }
    if (formsPostToMicrosoft(snapshot.forms)) {
        signals.push({
            id: "cross-origin-form",
            description: "Form actions point to Microsoft domains while served from an untrusted host."
        });
    }
    if (containsMicrosoftStrings(snapshot.html)) {
        signals.push({
            id: "inline-upstream-reference",
            description: "Inline source contains upstream Microsoft URLs on an untrusted host."
        });
    }
    const uniqueSignals = signals.filter((signal, index, arr) => arr.findIndex((candidate) => candidate.id === signal.id) === index);
    const score = uniqueSignals.length;
    if (score < options.threshold) {
        return null;
    }
    return {
        score,
        threshold: options.threshold,
        signals: uniqueSignals,
        matchedHost: hostname,
        pageUrl: snapshot.url
    };
}
//# sourceMappingURL=detector.js.map