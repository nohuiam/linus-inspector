/**
 * WebSocket Server
 *
 * Provides real-time inspection events and notifications.
 */

import { WebSocketServer, WebSocket } from 'ws';
import type { Server } from 'http';

export interface InspectionEvent {
  type: 'inspection_started' | 'inspection_progress' | 'inspection_complete' | 'issue_found' | 'connection_test';
  timestamp: string;
  data: any;
}

export function createWebSocketServer(httpServer: Server): WebSocketServer {
  const wss = new WebSocketServer({ server: httpServer });
  const clients: Set<WebSocket> = new Set();

  wss.on('connection', (ws: WebSocket) => {
    clients.add(ws);
    console.log(`[WebSocket] Client connected (${clients.size} total)`);

    // Send welcome message
    ws.send(JSON.stringify({
      type: 'connected',
      timestamp: new Date().toISOString(),
      data: {
        server: 'linus-inspector',
        version: '1.0.0'
      }
    }));

    ws.on('message', (message: Buffer) => {
      try {
        const data = JSON.parse(message.toString());
        handleClientMessage(ws, data);
      } catch (error: any) {
        const rawMessage = message.toString();
        console.error('[WebSocket] Invalid JSON from client:', error.message);
        console.error('[WebSocket] Raw message (first 200 chars):', rawMessage.substring(0, 200));
        ws.send(JSON.stringify({
          type: 'error',
          timestamp: new Date().toISOString(),
          data: { message: 'Invalid JSON message', detail: error.message }
        }));
      }
    });

    ws.on('close', () => {
      clients.delete(ws);
      console.log(`[WebSocket] Client disconnected (${clients.size} remaining)`);
    });

    ws.on('error', (error) => {
      console.error('[WebSocket] Client error:', error);
      clients.delete(ws);
    });
  });

  // Broadcast function for sending events to all clients
  const broadcast = (event: InspectionEvent) => {
    const message = JSON.stringify(event);
    for (const client of clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    }
  };

  // Attach broadcast function to wss for external access
  (wss as any).broadcast = broadcast;
  (wss as any).getClientCount = () => clients.size;

  console.log('[WebSocket] Server initialized');

  return wss;
}

function handleClientMessage(ws: WebSocket, data: any): void {
  switch (data.type) {
    case 'subscribe':
      // Could implement subscription filtering
      ws.send(JSON.stringify({
        type: 'subscribed',
        timestamp: new Date().toISOString(),
        data: { topics: data.topics || ['all'] }
      }));
      break;

    case 'ping':
      ws.send(JSON.stringify({
        type: 'pong',
        timestamp: new Date().toISOString(),
        data: {}
      }));
      break;

    default:
      ws.send(JSON.stringify({
        type: 'unknown_command',
        timestamp: new Date().toISOString(),
        data: { received: data.type }
      }));
  }
}

// Helper to broadcast inspection events
export function broadcastInspectionEvent(wss: WebSocketServer, event: InspectionEvent): void {
  const broadcast = (wss as any).broadcast;
  if (broadcast) {
    broadcast(event);
  }
}
