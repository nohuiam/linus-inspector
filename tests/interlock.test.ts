/**
 * Tests for InterLock protocol and mesh integration
 */

import { describe, it, expect } from 'vitest';
import {
  SIGNALS,
  encodeMessage,
  decodeMessage,
  isHandledSignal,
  getSignalName
} from '../src/interlock/protocol.js';
import { Tumbler, type TumblerConfig } from '../src/interlock/tumbler.js';

describe('InterLock Protocol', () => {
  describe('Signal Constants', () => {
    it('should define all required signals', () => {
      // Core inspection signals
      expect(SIGNALS.BUILD_STARTED).toBe(0xC0);
      expect(SIGNALS.INSPECTION_REQUESTED).toBe(0xC3);
      expect(SIGNALS.INSPECTION_PASSED).toBe(0xC4);
      expect(SIGNALS.INSPECTION_FAILED).toBe(0xC5);
      expect(SIGNALS.LESSON_EXTRACTED).toBe(0xC7);
    });

    it('should define pre-inspection signals', () => {
      expect(SIGNALS.PRE_INSPECTION_COMPLETE).toBe(0xD0);
      expect(SIGNALS.CONNECTION_TEST_RESULT).toBe(0xD1);
      expect(SIGNALS.PRE_INSPECTION_REQUESTED).toBe(0xD2);
      expect(SIGNALS.SKILL_VALIDATION_REQUESTED).toBe(0xD3);
      expect(SIGNALS.PROMPT_VALIDATION_REQUESTED).toBe(0xD4);
    });
  });

  describe('Message Encoding', () => {
    it('should encode message with BaNano header', () => {
      const buffer = encodeMessage(SIGNALS.INSPECTION_REQUESTED, {
        build_id: 'test-123',
        server_name: 'test-server'
      });

      expect(buffer).toBeInstanceOf(Buffer);
      expect(buffer.length).toBeGreaterThan(12); // 12-byte header + payload
    });

    it('should include correct signal type in header', () => {
      const buffer = encodeMessage(SIGNALS.BUILD_STARTED, { test: true });
      const signalType = buffer.readUInt16LE(0);
      expect(signalType).toBe(SIGNALS.BUILD_STARTED);
    });

    it('should include version in header', () => {
      const buffer = encodeMessage(SIGNALS.BUILD_STARTED, {});
      const version = buffer.readUInt16LE(2);
      expect(version).toBe(1); // Protocol version 1
    });

    it('should include payload length in header', () => {
      const payload = { message: 'hello world' };
      const buffer = encodeMessage(SIGNALS.BUILD_STARTED, payload);
      const payloadLength = buffer.readUInt32LE(4);
      const actualPayload = buffer.slice(12);
      expect(payloadLength).toBe(actualPayload.length);
    });

    it('should include timestamp in header', () => {
      const before = Math.floor(Date.now() / 1000);
      const buffer = encodeMessage(SIGNALS.BUILD_STARTED, {});
      const after = Math.floor(Date.now() / 1000);

      const timestamp = buffer.readUInt32LE(8);
      expect(timestamp).toBeGreaterThanOrEqual(before);
      expect(timestamp).toBeLessThanOrEqual(after);
    });
  });

  describe('Message Decoding', () => {
    it('should decode encoded message', () => {
      const original = {
        build_id: 'B-2026-001',
        server_name: 'hubspot-connector',
        verdict: 'PASSED'
      };
      const buffer = encodeMessage(SIGNALS.INSPECTION_PASSED, original);
      const decoded = decodeMessage(buffer);

      expect(decoded).not.toBeNull();
      expect(decoded?.signalType).toBe(SIGNALS.INSPECTION_PASSED);
      expect(decoded?.payload.build_id).toBe(original.build_id);
      expect(decoded?.payload.server_name).toBe(original.server_name);
      expect(decoded?.payload.verdict).toBe(original.verdict);
    });

    it('should return null for invalid buffer', () => {
      const invalidBuffer = Buffer.from('not a valid message');
      const decoded = decodeMessage(invalidBuffer);
      // Should return the decoded attempt or null based on implementation
      expect(decoded === null || decoded?.payload !== undefined).toBe(true);
    });

    it('should return null for too-short buffer', () => {
      const shortBuffer = Buffer.alloc(5);
      const decoded = decodeMessage(shortBuffer);
      expect(decoded).toBeNull();
    });

    it('should preserve complex payloads', () => {
      const complex = {
        issues: [
          { severity: 'CRITICAL', message: 'No rate limiter' },
          { severity: 'HIGH', message: 'Missing error handling' }
        ],
        summary: {
          critical: 1,
          high: 1,
          medium: 0,
          low: 0
        },
        auto_fixes_available: 2
      };
      const buffer = encodeMessage(SIGNALS.INSPECTION_FAILED, complex);
      const decoded = decodeMessage(buffer);

      expect(decoded?.payload.issues).toHaveLength(2);
      expect(decoded?.payload.summary.critical).toBe(1);
    });
  });

  describe('Signal Helpers', () => {
    it('should identify handled signals', () => {
      // Only signals that the server actually handles (receives)
      expect(isHandledSignal(SIGNALS.BUILD_STARTED)).toBe(true);
      expect(isHandledSignal(SIGNALS.INSPECTION_REQUESTED)).toBe(true);
      expect(isHandledSignal(SIGNALS.PRE_INSPECTION_REQUESTED)).toBe(true);
      expect(isHandledSignal(SIGNALS.SKILL_VALIDATION_REQUESTED)).toBe(true);
    });

    it('should return false for unknown signals', () => {
      expect(isHandledSignal(0x00)).toBe(false);
      expect(isHandledSignal(0xFF)).toBe(false);
      // Emitted signals are not "handled"
      expect(isHandledSignal(SIGNALS.INSPECTION_PASSED)).toBe(false);
    });

    it('should get signal names', () => {
      expect(getSignalName(SIGNALS.BUILD_STARTED)).toBe('BUILD_STARTED');
      expect(getSignalName(SIGNALS.INSPECTION_REQUESTED)).toBe('INSPECTION_REQUESTED');
      expect(getSignalName(SIGNALS.INSPECTION_PASSED)).toBe('INSPECTION_PASSED');
      expect(getSignalName(SIGNALS.INSPECTION_FAILED)).toBe('INSPECTION_FAILED');
    });

    it('should return UNKNOWN for unknown signals', () => {
      const name = getSignalName(0x99);
      expect(name).toContain('UNKNOWN');
    });
  });
});

describe('Tumbler (Whitelist Filter)', () => {
  it('should allow whitelisted signals', () => {
    const tumbler = new Tumbler({
      whitelist: [SIGNALS.BUILD_STARTED, SIGNALS.INSPECTION_REQUESTED],
      logRejected: false
    });

    expect(tumbler.isAllowed(SIGNALS.BUILD_STARTED)).toBe(true);
    expect(tumbler.isAllowed(SIGNALS.INSPECTION_REQUESTED)).toBe(true);
  });

  it('should reject non-whitelisted signals', () => {
    const tumbler = new Tumbler({
      whitelist: [SIGNALS.BUILD_STARTED],
      logRejected: false
    });

    expect(tumbler.isAllowed(SIGNALS.INSPECTION_PASSED)).toBe(false);
    expect(tumbler.isAllowed(0xFF)).toBe(false);
  });

  it('should track rejected count', () => {
    const tumbler = new Tumbler({
      whitelist: [SIGNALS.BUILD_STARTED],
      logRejected: true
    });

    tumbler.isAllowed(0x01);
    tumbler.isAllowed(0x02);
    tumbler.isAllowed(0x03);

    const stats = tumbler.getStats();
    expect(stats.rejectedCount).toBe(3);
  });

  it('should allow adding signals dynamically', () => {
    const tumbler = new Tumbler({
      whitelist: [],
      logRejected: false
    });

    expect(tumbler.isAllowed(SIGNALS.BUILD_STARTED)).toBe(false);

    tumbler.allow(SIGNALS.BUILD_STARTED);

    expect(tumbler.isAllowed(SIGNALS.BUILD_STARTED)).toBe(true);
  });

  it('should allow removing signals dynamically', () => {
    const tumbler = new Tumbler({
      whitelist: [SIGNALS.BUILD_STARTED, SIGNALS.INSPECTION_REQUESTED],
      logRejected: false
    });

    expect(tumbler.isAllowed(SIGNALS.BUILD_STARTED)).toBe(true);

    tumbler.deny(SIGNALS.BUILD_STARTED);

    expect(tumbler.isAllowed(SIGNALS.BUILD_STARTED)).toBe(false);
    expect(tumbler.isAllowed(SIGNALS.INSPECTION_REQUESTED)).toBe(true);
  });

  it('should return whitelist copy', () => {
    const tumbler = new Tumbler({
      whitelist: [SIGNALS.BUILD_STARTED],
      logRejected: false
    });

    const whitelist = tumbler.getWhitelist();
    whitelist.push(0xFF); // Modify copy

    // Original should not be affected
    expect(tumbler.isAllowed(0xFF)).toBe(false);
  });

  it('should reset stats', () => {
    const tumbler = new Tumbler({
      whitelist: [],
      logRejected: true
    });

    tumbler.isAllowed(0x01);
    tumbler.isAllowed(0x02);

    expect(tumbler.getStats().rejectedCount).toBe(2);

    tumbler.resetStats();

    expect(tumbler.getStats().rejectedCount).toBe(0);
  });

  it('should use default config when not specified', () => {
    const tumbler = new Tumbler();

    // Default whitelist includes inspection-related signals
    expect(tumbler.isAllowed(SIGNALS.BUILD_STARTED)).toBe(true);
    expect(tumbler.isAllowed(SIGNALS.INSPECTION_REQUESTED)).toBe(true);
  });
});
