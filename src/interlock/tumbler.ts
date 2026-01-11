/**
 * InterLock Tumbler
 *
 * Whitelist filter for allowed signals.
 * Only signals in the whitelist are processed.
 */

import { SIGNALS, isHandledSignal, getSignalName } from './protocol.js';

export interface TumblerConfig {
  whitelist: number[];
  logRejected: boolean;
}

const DEFAULT_CONFIG: TumblerConfig = {
  whitelist: [
    SIGNALS.BUILD_STARTED,
    SIGNALS.INSPECTION_REQUESTED,
    SIGNALS.PRE_INSPECTION_REQUESTED,
    SIGNALS.SKILL_VALIDATION_REQUESTED,
    SIGNALS.PROMPT_VALIDATION_REQUESTED
  ],
  logRejected: false
};

export class Tumbler {
  private config: TumblerConfig;
  private rejectedCount: number = 0;

  constructor(config: Partial<TumblerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Check if a signal is allowed
   */
  isAllowed(signalType: number): boolean {
    const allowed = this.config.whitelist.includes(signalType);

    if (!allowed && this.config.logRejected) {
      this.rejectedCount++;
      console.log(`[Tumbler] Rejected signal ${getSignalName(signalType)} (${this.rejectedCount} total rejected)`);
    }

    return allowed;
  }

  /**
   * Add signal to whitelist
   */
  allow(signalType: number): void {
    if (!this.config.whitelist.includes(signalType)) {
      this.config.whitelist.push(signalType);
    }
  }

  /**
   * Remove signal from whitelist
   */
  deny(signalType: number): void {
    this.config.whitelist = this.config.whitelist.filter(s => s !== signalType);
  }

  /**
   * Get whitelist
   */
  getWhitelist(): number[] {
    return [...this.config.whitelist];
  }

  /**
   * Get stats
   */
  getStats(): { whitelistSize: number; rejectedCount: number } {
    return {
      whitelistSize: this.config.whitelist.length,
      rejectedCount: this.rejectedCount
    };
  }

  /**
   * Reset rejected count
   */
  resetStats(): void {
    this.rejectedCount = 0;
  }
}

// Default tumbler instance
export const defaultTumbler = new Tumbler();
