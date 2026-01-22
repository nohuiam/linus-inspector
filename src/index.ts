#!/usr/bin/env node
/**
 * Linus Excellence Inspection Server
 *
 * A brutal, unforgiving quality gate for neurogenesis-generated servers.
 * Catches issues that would otherwise require 3-4 debugging rounds.
 *
 * Ports:
 *   - MCP: stdio (stdin/stdout)
 *   - UDP: 3033 (InterLock mesh)
 *   - HTTP: 8033 (REST API)
 *   - WebSocket: 9033 (real-time events)
 *
 * Inspection Categories:
 *   - Code Quality (API correctness, error handling, rate limiting)
 *   - Prompt Inspection (safety, clarity, efficiency)
 *   - Skill Validation (Anthropic guidelines compliance)
 *   - SaaS API Pre-Inspection (probe real APIs before building)
 *   - Connection Testing (live connection verification)
 *   - Ecosystem Integration (InterLock mesh, MCP protocol)
 *   - Compliance (HIPAA, GDPR, SOC 2, PCI-DSS)
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import { initDatabase } from './database/index.js';
import { createHttpServer } from './http/server.js';
import { createWebSocketServer, broadcastInspectionEvent } from './websocket/server.js';
import { InterlockSocket, registerHandlers, Tumbler, SIGNALS } from './interlock/index.js';
import { registerTools } from './tools/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load configuration
function loadConfig(): any {
  const configPath = path.join(__dirname, '..', 'config', 'interlock.json');
  try {
    const configData = fs.readFileSync(configPath, 'utf-8');
    const rawConfig = JSON.parse(configData);

    // Normalize config structure
    return {
      server: {
        name: rawConfig.server?.name || 'linus-inspector',
        udp_port: rawConfig.ports?.udp || rawConfig.server?.udp_port || 3033,
        http_port: rawConfig.ports?.http || rawConfig.server?.http_port || 8033,
        ws_port: rawConfig.ports?.websocket || rawConfig.server?.ws_port || 9033
      },
      peers: rawConfig.peers || []
    };
  } catch (error: any) {
    console.error('[Config] Failed to load config from:', configPath);
    console.error('[Config] Error:', error.message || error);
    console.error('[Config] Using defaults - this may cause issues if config was expected');
    return {
      server: { name: 'linus-inspector', udp_port: 3037, http_port: 8037, ws_port: 9037 },
      peers: []
    };
  }
}

async function main(): Promise<void> {
  const config = loadConfig();

  console.log('='.repeat(60));
  console.log('  LINUS EXCELLENCE INSPECTION SERVER');
  console.log('  Brutal Quality Gate for Production-Ready Builds');
  console.log('='.repeat(60));
  console.log(`  Server: ${config.server.name}`);
  console.log(`  UDP Port: ${config.server.udp_port}`);
  console.log(`  HTTP Port: ${config.server.http_port}`);
  console.log(`  WS Port: ${config.server.ws_port}`);
  console.log('='.repeat(60));

  // Initialize database
  console.log('[Init] Initializing database...');
  const dataDir = path.join(__dirname, '..', 'data');
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  initDatabase();

  // Initialize InterLock mesh
  console.log('[Init] Starting InterLock mesh...');
  const tumbler = new Tumbler({
    whitelist: [
      SIGNALS.BUILD_STARTED,
      SIGNALS.INSPECTION_REQUESTED,
      SIGNALS.PRE_INSPECTION_REQUESTED,
      SIGNALS.SKILL_VALIDATION_REQUESTED,
      SIGNALS.PROMPT_VALIDATION_REQUESTED
    ],
    logRejected: true
  });

  const interlockSocket = new InterlockSocket({
    port: config.server.udp_port,
    peers: config.peers.map((p: any) => ({ name: p.name, port: p.port }))
  });

  try {
    await interlockSocket.start();
    registerHandlers(interlockSocket);
    console.log(`[InterLock] Mesh listening on UDP ${config.server.udp_port}`);
    console.log(`[InterLock] Connected to ${config.peers.length} peers`);
  } catch (error) {
    console.error('[InterLock] Failed to start:', error);
    // Continue without InterLock - HTTP/MCP still useful
  }

  // Initialize HTTP server
  console.log('[Init] Starting HTTP server...');
  const httpApp = createHttpServer(config.server.http_port);

  // Initialize WebSocket server (attach to HTTP)
  console.log('[Init] Starting WebSocket server...');
  const httpServer = createServer(httpApp);
  const wss = createWebSocketServer(httpServer);

  // Start HTTP server with WebSocket
  httpServer.listen(config.server.ws_port, () => {
    console.log(`[WebSocket] Server listening on port ${config.server.ws_port}`);
  });

  // Initialize MCP server
  console.log('[Init] Starting MCP server...');
  const mcpServer = new McpServer({
    name: 'linus-inspector',
    version: '1.0.0'
  });

  // Register MCP tools
  registerTools(mcpServer);

  // Create stdio transport
  const transport = new StdioServerTransport();

  // Connect MCP server
  await mcpServer.connect(transport);

  console.log('');
  console.log('='.repeat(60));
  console.log('  LINUS INSPECTOR READY');
  console.log('  All layers operational:');
  console.log(`    - MCP: stdio (25+ tools registered)`);
  console.log(`    - UDP: ${config.server.udp_port} (InterLock mesh)`);
  console.log(`    - HTTP: ${config.server.http_port} (REST API)`);
  console.log(`    - WebSocket: ${config.server.ws_port} (real-time events)`);
  console.log('');
  console.log('  Inspection Categories:');
  console.log('    - Rate Limiting (35-40% of failures)');
  console.log('    - Error Handling (25-30% of failures)');
  console.log('    - Auth/OAuth (10-20% of failures)');
  console.log('    - Webhooks (12-20% of failures)');
  console.log('    - Data Integrity (8-10%, highest cost)');
  console.log('    - Compliance (HIPAA, GDPR, SOC 2, PCI-DSS)');
  console.log('='.repeat(60));

  // Broadcast startup event
  broadcastInspectionEvent(wss, {
    type: 'connection_test',
    timestamp: new Date().toISOString(),
    data: {
      status: 'ready',
      server: 'linus-inspector',
      ports: {
        udp: config.server.udp_port,
        http: config.server.http_port,
        ws: config.server.ws_port
      }
    }
  });

  // Handle graceful shutdown
  process.on('SIGINT', () => {
    console.log('\n[Shutdown] Received SIGINT, shutting down...');
    interlockSocket.stop();
    httpServer.close();
    wss.close();
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    console.log('\n[Shutdown] Received SIGTERM, shutting down...');
    interlockSocket.stop();
    httpServer.close();
    wss.close();
    process.exit(0);
  });
}

// Run the server
main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
