/**
 * InterLock BaNano Protocol
 *
 * 12-byte binary header format:
 * - signalType: uint16 (2 bytes)
 * - version: uint16 (2 bytes)
 * - payloadLen: uint32 (4 bytes)
 * - timestamp: uint32 (4 bytes)
 * + JSON payload
 */

export const PROTOCOL_VERSION = 1;
export const HEADER_SIZE = 12;

// Signal codes for linus-inspector
export const SIGNALS = {
  // Emits
  INSPECTION_PASSED: 0xC4,
  INSPECTION_FAILED: 0xC5,
  LESSON_EXTRACTED: 0xC7,
  PRE_INSPECTION_COMPLETE: 0xD0,
  CONNECTION_TEST_RESULT: 0xD1,

  // Receives
  BUILD_STARTED: 0xC0,
  INSPECTION_REQUESTED: 0xC3,
  PRE_INSPECTION_REQUESTED: 0xD2,
  SKILL_VALIDATION_REQUESTED: 0xD3,
  PROMPT_VALIDATION_REQUESTED: 0xD4
} as const;

export type SignalCode = typeof SIGNALS[keyof typeof SIGNALS];

export interface BaNanoMessage {
  signalType: number;
  version: number;
  timestamp: number;
  payload: any;
}

/**
 * Encode a message to BaNano binary format
 */
export function encodeMessage(signalType: number, payload: any): Buffer {
  const payloadStr = JSON.stringify(payload);
  const payloadBuf = Buffer.from(payloadStr, 'utf-8');

  const header = Buffer.alloc(HEADER_SIZE);
  header.writeUInt16LE(signalType, 0);
  header.writeUInt16LE(PROTOCOL_VERSION, 2);
  header.writeUInt32LE(payloadBuf.length, 4);
  header.writeUInt32LE(Math.floor(Date.now() / 1000), 8);

  return Buffer.concat([header, payloadBuf]);
}

/**
 * Decode a BaNano binary message
 */
export function decodeMessage(buffer: Buffer): BaNanoMessage | null {
  if (buffer.length < HEADER_SIZE) {
    return null;
  }

  const signalType = buffer.readUInt16LE(0);
  const version = buffer.readUInt16LE(2);
  const payloadLen = buffer.readUInt32LE(4);
  const timestamp = buffer.readUInt32LE(8);

  if (buffer.length < HEADER_SIZE + payloadLen) {
    return null;
  }

  let payload: any = null;
  if (payloadLen > 0) {
    const payloadBuf = buffer.subarray(HEADER_SIZE, HEADER_SIZE + payloadLen);
    try {
      payload = JSON.parse(payloadBuf.toString('utf-8'));
    } catch {
      // Invalid JSON payload
      return null;
    }
  }

  return { signalType, version, timestamp, payload };
}

/**
 * Get signal name from code
 */
export function getSignalName(code: number): string {
  for (const [name, signalCode] of Object.entries(SIGNALS)) {
    if (signalCode === code) {
      return name;
    }
  }
  return `UNKNOWN_${code.toString(16)}`;
}

/**
 * Check if signal is one we handle
 */
export function isHandledSignal(code: number): boolean {
  return [
    SIGNALS.BUILD_STARTED,
    SIGNALS.INSPECTION_REQUESTED,
    SIGNALS.PRE_INSPECTION_REQUESTED,
    SIGNALS.SKILL_VALIDATION_REQUESTED,
    SIGNALS.PROMPT_VALIDATION_REQUESTED
  ].includes(code as any);
}
