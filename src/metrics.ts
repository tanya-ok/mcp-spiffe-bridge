import type { BridgeCounter, BridgeHistogram, BridgeMetrics } from './types.js';

/** Call metrics hooks without letting them affect authentication. */
export class Metrics {
  constructor(private readonly hooks: BridgeMetrics | undefined) {}

  increment(name: BridgeCounter, labels?: Readonly<Record<string, string>>): void {
    try {
      this.hooks?.increment?.(name, labels);
    } catch {
      /* Metrics must never change authentication outcomes. */
    }
  }

  observe(name: BridgeHistogram, value: number, labels?: Readonly<Record<string, string>>): void {
    try {
      this.hooks?.observe?.(name, value, labels);
    } catch {
      /* Metrics must never change authentication outcomes. */
    }
  }
}
