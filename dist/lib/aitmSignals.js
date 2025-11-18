export const DEFAULT_THRESHOLD = 70;
const DEFAULT_WEIGHTS = {
    low: 10,
    medium: 25,
    high: 50
};
const SEVERITY_RANK = {
    low: 1,
    medium: 2,
    high: 3
};
export function computeScore(signals, weights = DEFAULT_WEIGHTS) {
    return signals.reduce((total, signal) => {
        return total + weights[signal.severity];
    }, 0);
}
export function evaluateSignals(signals, options = {}) {
    const threshold = options.threshold ?? DEFAULT_THRESHOLD;
    const weights = {
        ...DEFAULT_WEIGHTS,
        ...options.weights
    };
    const score = computeScore(signals, weights);
    return {
        score,
        threshold,
        triggered: score >= threshold,
        signals
    };
}
export const MICROSOFT_HOST_PATTERNS = [
    /^login\.microsoftonline\.com$/,
    /^login\.windows\.net$/,
    /^([a-z0-9-]+\.)*microsoftonline\.com$/,
    /^([a-z0-9-]+\.)*microsoft\.com$/
];
export function isMicrosoftHost(host) {
    return MICROSOFT_HOST_PATTERNS.some((pattern) => pattern.test(host));
}
export function mergeSignalCollections(...collections) {
    const merged = new Map();
    for (const collection of collections) {
        for (const signal of collection) {
            const existing = merged.get(signal.id);
            if (!existing) {
                merged.set(signal.id, { ...signal });
                continue;
            }
            if (SEVERITY_RANK[signal.severity] > SEVERITY_RANK[existing.severity]) {
                merged.set(signal.id, { ...signal });
            }
            else if (SEVERITY_RANK[signal.severity] === SEVERITY_RANK[existing.severity]) {
                merged.set(signal.id, {
                    ...existing,
                    evidence: {
                        ...existing.evidence,
                        ...signal.evidence
                    }
                });
            }
        }
    }
    return Array.from(merged.values());
}
