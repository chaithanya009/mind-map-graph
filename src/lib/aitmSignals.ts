export type SignalSeverity = "low" | "medium" | "high";

export interface SignalObservation {
  id: string;
  severity: SignalSeverity;
  description: string;
  evidence?: Record<string, unknown>;
}

export interface DetectionResult {
  score: number;
  threshold: number;
  triggered: boolean;
  signals: SignalObservation[];
}

export interface ScoreWeights {
  low: number;
  medium: number;
  high: number;
}

export interface EvaluateOptions {
  threshold?: number;
  weights?: Partial<ScoreWeights>;
}

export const DEFAULT_THRESHOLD = 70;

const DEFAULT_WEIGHTS: ScoreWeights = {
  low: 10,
  medium: 25,
  high: 50
};

const SEVERITY_RANK: Record<SignalSeverity, number> = {
  low: 1,
  medium: 2,
  high: 3
};

export function computeScore(
  signals: SignalObservation[],
  weights: ScoreWeights = DEFAULT_WEIGHTS
): number {
  return signals.reduce((total, signal) => {
    return total + weights[signal.severity];
  }, 0);
}

export function evaluateSignals(
  signals: SignalObservation[],
  options: EvaluateOptions = {}
): DetectionResult {
  const threshold = options.threshold ?? DEFAULT_THRESHOLD;
  const weights: ScoreWeights = {
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

export const MICROSOFT_HOST_PATTERNS: RegExp[] = [
  /^login\.microsoftonline\.com$/,
  /^login\.windows\.net$/,
  /^([a-z0-9-]+\.)*microsoftonline\.com$/,
  /^([a-z0-9-]+\.)*microsoft\.com$/
];

export function isMicrosoftHost(host: string): boolean {
  return MICROSOFT_HOST_PATTERNS.some((pattern) => pattern.test(host));
}

export function mergeSignalCollections(
  ...collections: SignalObservation[][]
): SignalObservation[] {
  const merged = new Map<string, SignalObservation>();

  for (const collection of collections) {
    for (const signal of collection) {
      const existing = merged.get(signal.id);
      if (!existing) {
        merged.set(signal.id, { ...signal });
        continue;
      }
      if (SEVERITY_RANK[signal.severity] > SEVERITY_RANK[existing.severity]) {
        merged.set(signal.id, { ...signal });
      } else if (SEVERITY_RANK[signal.severity] === SEVERITY_RANK[existing.severity]) {
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

