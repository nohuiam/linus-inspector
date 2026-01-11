/**
 * InterLock UDP Socket
 *
 * Handles UDP communication for the InterLock mesh network.
 */

import dgram from 'dgram';
import { encodeMessage, decodeMessage, type BaNanoMessage } from './protocol.js';

export interface InterlockConfig {
  port: number;
  peers: Array<{ name: string; port: number }>;
}

export type MessageHandler = (message: BaNanoMessage, rinfo: dgram.RemoteInfo) => void;

export class InterlockSocket {
  private socket: dgram.Socket | null = null;
  private config: InterlockConfig;
  private handlers: Map<number, MessageHandler[]> = new Map();
  private globalHandlers: MessageHandler[] = [];

  constructor(config: InterlockConfig) {
    this.config = config;
  }

  /**
   * Start the UDP socket
   */
  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket = dgram.createSocket('udp4');

      this.socket.on('error', (err) => {
        console.error(`InterLock socket error: ${err.message}`);
        reject(err);
      });

      this.socket.on('message', (msg, rinfo) => {
        this.handleMessage(msg, rinfo);
      });

      this.socket.on('listening', () => {
        const address = this.socket?.address();
        console.log(`InterLock listening on ${address?.address}:${address?.port}`);
        resolve();
      });

      this.socket.bind(this.config.port);
    });
  }

  /**
   * Stop the UDP socket
   */
  stop(): void {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
  }

  /**
   * Handle incoming message
   */
  private handleMessage(buffer: Buffer, rinfo: dgram.RemoteInfo): void {
    const message = decodeMessage(buffer);
    if (!message) {
      console.warn(`Invalid message from ${rinfo.address}:${rinfo.port}`);
      return;
    }

    // Call signal-specific handlers
    const signalHandlers = this.handlers.get(message.signalType) || [];
    for (const handler of signalHandlers) {
      try {
        handler(message, rinfo);
      } catch (error) {
        console.error(`Handler error for signal ${message.signalType}:`, error);
      }
    }

    // Call global handlers
    for (const handler of this.globalHandlers) {
      try {
        handler(message, rinfo);
      } catch (error) {
        console.error('Global handler error:', error);
      }
    }
  }

  /**
   * Register handler for specific signal type
   */
  on(signalType: number, handler: MessageHandler): void {
    const existing = this.handlers.get(signalType) || [];
    existing.push(handler);
    this.handlers.set(signalType, existing);
  }

  /**
   * Register handler for all messages
   */
  onAny(handler: MessageHandler): void {
    this.globalHandlers.push(handler);
  }

  /**
   * Send message to a specific port
   */
  send(signalType: number, payload: any, port: number): void {
    if (!this.socket) {
      console.warn('Socket not started, cannot send');
      return;
    }

    const message = encodeMessage(signalType, payload);
    this.socket.send(message, port, '127.0.0.1', (err) => {
      if (err) {
        console.error(`Failed to send to port ${port}:`, err);
      }
    });
  }

  /**
   * Broadcast message to all peers
   */
  broadcast(signalType: number, payload: any): void {
    for (const peer of this.config.peers) {
      this.send(signalType, payload, peer.port);
    }
  }

  /**
   * Send message to specific peer by name
   */
  sendToPeer(peerName: string, signalType: number, payload: any): boolean {
    const peer = this.config.peers.find(p => p.name === peerName);
    if (!peer) {
      console.warn(`Unknown peer: ${peerName}`);
      return false;
    }
    this.send(signalType, payload, peer.port);
    return true;
  }

  /**
   * Get socket address
   */
  getAddress(): { port: number; address: string; family: string } | null {
    return this.socket?.address() as { port: number; address: string; family: string } || null;
  }
}
