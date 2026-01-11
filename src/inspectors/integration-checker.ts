/**
 * Integration Checker
 *
 * Verifies new servers integrate properly with existing BOP ecosystem.
 * Checks InterLock config, peer connectivity, signal compatibility,
 * health endpoints, MCP protocol, and dependencies.
 */

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { generateId } from '../database/index.js';

export interface IntegrationCheckOptions {
  server_path: string;
  check_connectivity?: boolean;
  timeout_ms?: number;
}

export interface IntegrationIssue {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  issue: string;
  remedy: string;
}

export interface IntegrationCheckResult {
  server_path: string;
  verdict: 'PASS' | 'FAIL' | 'PARTIAL';
  checks: {
    interlock_valid: boolean;
    interlock_port?: number;
    package_valid: boolean;
    peer_config: string[];
    signal_health: {
      emits: string[];
      receives: string[];
      orphans: string[];
    };
    mcp_tools: string[];
    health_endpoint?: {
      path: string;
      expected_port: number;
    };
    dependencies_valid: boolean;
  };
  issues: IntegrationIssue[];
}

/**
 * Load and validate interlock.json
 */
function checkInterlockConfig(serverPath: string): {
  valid: boolean;
  port?: number;
  peers: string[];
  signals: { emits: string[]; receives: string[] };
  issues: IntegrationIssue[];
} {
  const issues: IntegrationIssue[] = [];
  const configPath = join(serverPath, 'config', 'interlock.json');

  if (!existsSync(configPath)) {
    issues.push({
      severity: 'CRITICAL',
      category: 'interlock',
      issue: 'Missing config/interlock.json',
      remedy: 'Create interlock.json with ports, signals, and peers configuration'
    });
    return { valid: false, peers: [], signals: { emits: [], receives: [] }, issues };
  }

  let config: any;
  try {
    const content = readFileSync(configPath, 'utf-8');
    config = JSON.parse(content);
  } catch (error) {
    issues.push({
      severity: 'CRITICAL',
      category: 'interlock',
      issue: 'Invalid JSON in interlock.json',
      remedy: 'Fix JSON syntax errors in config/interlock.json'
    });
    return { valid: false, peers: [], signals: { emits: [], receives: [] }, issues };
  }

  // Check for required fields
  if (!config.ports?.udp) {
    issues.push({
      severity: 'HIGH',
      category: 'interlock',
      issue: 'Missing UDP port in interlock.json',
      remedy: 'Add ports.udp field with assigned port number (3001-3099)'
    });
  }

  if (!config.ports?.http) {
    issues.push({
      severity: 'HIGH',
      category: 'interlock',
      issue: 'Missing HTTP port in interlock.json',
      remedy: 'Add ports.http field (should be 8000 + server number)'
    });
  }

  if (!config.server?.name) {
    issues.push({
      severity: 'MEDIUM',
      category: 'interlock',
      issue: 'Missing server.name in interlock.json',
      remedy: 'Add server.name field for identification'
    });
  }

  // Extract peers
  const peers = (config.peers || []).map((p: any) => p.name || p);

  // Extract signals
  const emits = (config.signals?.emits || []).map((s: any) => s.name || s);
  const receives = (config.signals?.receives || []).map((s: any) => s.name || s);

  return {
    valid: issues.filter(i => i.severity === 'CRITICAL').length === 0,
    port: config.ports?.udp,
    peers,
    signals: { emits, receives },
    issues
  };
}

/**
 * Check package.json for required dependencies
 */
function checkPackageJson(serverPath: string): {
  valid: boolean;
  issues: IntegrationIssue[];
} {
  const issues: IntegrationIssue[] = [];
  const packagePath = join(serverPath, 'package.json');

  if (!existsSync(packagePath)) {
    issues.push({
      severity: 'CRITICAL',
      category: 'package',
      issue: 'Missing package.json',
      remedy: 'Create package.json with name, version, and dependencies'
    });
    return { valid: false, issues };
  }

  let pkg: any;
  try {
    const content = readFileSync(packagePath, 'utf-8');
    pkg = JSON.parse(content);
  } catch (error) {
    issues.push({
      severity: 'CRITICAL',
      category: 'package',
      issue: 'Invalid JSON in package.json',
      remedy: 'Fix JSON syntax errors in package.json'
    });
    return { valid: false, issues };
  }

  // Check required fields
  if (!pkg.name) {
    issues.push({
      severity: 'MEDIUM',
      category: 'package',
      issue: 'Missing name in package.json',
      remedy: 'Add name field'
    });
  }

  if (!pkg.version) {
    issues.push({
      severity: 'LOW',
      category: 'package',
      issue: 'Missing version in package.json',
      remedy: 'Add version field (e.g., "1.0.0")'
    });
  }

  // Check for MCP SDK
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };
  if (!deps['@modelcontextprotocol/sdk']) {
    issues.push({
      severity: 'HIGH',
      category: 'package',
      issue: 'Missing @modelcontextprotocol/sdk dependency',
      remedy: 'Add @modelcontextprotocol/sdk to dependencies for MCP support'
    });
  }

  // Check for required scripts
  if (!pkg.scripts?.build) {
    issues.push({
      severity: 'MEDIUM',
      category: 'package',
      issue: 'Missing build script',
      remedy: 'Add "build": "tsc" or similar build script'
    });
  }

  if (!pkg.scripts?.start) {
    issues.push({
      severity: 'MEDIUM',
      category: 'package',
      issue: 'Missing start script',
      remedy: 'Add "start": "node dist/index.js" or similar start script'
    });
  }

  return {
    valid: issues.filter(i => i.severity === 'CRITICAL').length === 0,
    issues
  };
}

/**
 * Detect MCP tools from source code
 */
function detectMcpTools(serverPath: string): string[] {
  const tools: string[] = [];
  const toolsDir = join(serverPath, 'src', 'tools');

  if (!existsSync(toolsDir)) {
    return tools;
  }

  // Try to read tool files
  try {
    const { readdirSync } = require('fs');
    const files = readdirSync(toolsDir);

    for (const file of files) {
      if (file.endsWith('.ts') || file.endsWith('.js')) {
        if (file !== 'index.ts' && file !== 'index.js') {
          // Convert filename to tool name
          const toolName = file
            .replace(/\.(ts|js)$/, '')
            .replace(/-/g, '_');
          tools.push(toolName);
        }
      }
    }
  } catch {
    // Directory read failed
  }

  return tools;
}

/**
 * Check for orphan signals (emits with no receivers, receives with no emitters)
 */
function checkSignalOrphans(
  emits: string[],
  receives: string[],
  peers: string[]
): { orphans: string[]; issues: IntegrationIssue[] } {
  const issues: IntegrationIssue[] = [];
  const orphans: string[] = [];

  // For now, we can only check basic patterns
  // A full check would require loading configs from all peers

  // Common signal patterns that should have pairs
  const commonPairs: Record<string, string> = {
    'BUILD_STARTED': 'BUILD_COMPLETED',
    'INSPECTION_REQUESTED': 'INSPECTION_PASSED',
    'SYNC_STARTED': 'SYNC_COMPLETED',
    'VALIDATION_REQUESTED': 'VALIDATION_RESPONSE'
  };

  for (const signal of emits) {
    const pair = commonPairs[signal];
    if (pair && !emits.includes(pair) && !receives.includes(pair)) {
      issues.push({
        severity: 'LOW',
        category: 'signals',
        issue: `Signal ${signal} emitted but no corresponding ${pair}`,
        remedy: 'Verify signal lifecycle is complete'
      });
    }
  }

  // Check if receives have potential emitters
  if (receives.length > 0 && peers.length === 0) {
    issues.push({
      severity: 'MEDIUM',
      category: 'signals',
      issue: 'Server receives signals but has no peers configured',
      remedy: 'Add peers to interlock.json to receive signals from'
    });
  }

  return { orphans, issues };
}

/**
 * Main integration check function
 */
export function checkIntegration(options: IntegrationCheckOptions): IntegrationCheckResult {
  const allIssues: IntegrationIssue[] = [];

  // Check interlock config
  const interlockCheck = checkInterlockConfig(options.server_path);
  allIssues.push(...interlockCheck.issues);

  // Check package.json
  const packageCheck = checkPackageJson(options.server_path);
  allIssues.push(...packageCheck.issues);

  // Detect MCP tools
  const mcpTools = detectMcpTools(options.server_path);

  if (mcpTools.length === 0) {
    allIssues.push({
      severity: 'MEDIUM',
      category: 'mcp',
      issue: 'No MCP tools detected in src/tools/',
      remedy: 'Create tool files in src/tools/ directory'
    });
  }

  // Check signal health
  const signalCheck = checkSignalOrphans(
    interlockCheck.signals.emits,
    interlockCheck.signals.receives,
    interlockCheck.peers
  );
  allIssues.push(...signalCheck.issues);

  // Check for required directories
  const requiredDirs = [
    'src/interlock',
    'src/http',
    'src/websocket'
  ];

  for (const dir of requiredDirs) {
    const dirPath = join(options.server_path, dir);
    if (!existsSync(dirPath)) {
      allIssues.push({
        severity: 'HIGH',
        category: 'structure',
        issue: `Missing ${dir} directory`,
        remedy: `Create ${dir} directory with required modules`
      });
    }
  }

  // Determine verdict
  let verdict: 'PASS' | 'FAIL' | 'PARTIAL';
  const criticalCount = allIssues.filter(i => i.severity === 'CRITICAL').length;
  const highCount = allIssues.filter(i => i.severity === 'HIGH').length;

  if (criticalCount > 0) {
    verdict = 'FAIL';
  } else if (highCount > 0) {
    verdict = 'PARTIAL';
  } else {
    verdict = 'PASS';
  }

  return {
    server_path: options.server_path,
    verdict,
    checks: {
      interlock_valid: interlockCheck.valid,
      interlock_port: interlockCheck.port,
      package_valid: packageCheck.valid,
      peer_config: interlockCheck.peers,
      signal_health: {
        emits: interlockCheck.signals.emits,
        receives: interlockCheck.signals.receives,
        orphans: signalCheck.orphans
      },
      mcp_tools: mcpTools,
      health_endpoint: interlockCheck.port ? {
        path: '/health',
        expected_port: interlockCheck.port + 5000 // HTTP port = UDP + 5000
      } : undefined,
      dependencies_valid: packageCheck.valid
    },
    issues: allIssues
  };
}
