/**
 * Server Profile Detector
 *
 * Analyzes source code to detect server capabilities and classify server type.
 * Uses pattern matching to identify what features a server has.
 */

import { readFileSync } from 'fs';
import { glob } from 'glob';
import { join } from 'path';
import {
  ServerProfile,
  createEmptyProfile,
  classifyServerType,
  calculateConfidence
} from './server-profile.js';

// Known external API domains (not localhost/internal)
const EXTERNAL_DOMAINS = [
  // Cloud providers
  'amazonaws.com', 'azure.com', 'googleapis.com', 'cloudflare.com',
  // SaaS vendors
  'salesforce.com', 'force.com', 'hubapi.com', 'hubspot.com',
  'stripe.com', 'snowflakecomputing.com', 'zendesk.com',
  'slack.com', 'intuit.com', 'quickbooks', 'shopify.com',
  'service-now.com', 'servicenow', 'graph.microsoft.com',
  // AI/ML
  'openai.com', 'anthropic.com', 'api.openai', 'api.anthropic',
  // Generic API indicators
  'api\\.', '\\.api\\.'
];

// Internal/local patterns
const INTERNAL_PATTERNS = [
  'localhost', '127\\.0\\.0\\.1', '0\\.0\\.0\\.0',
  'internal\\.', 'local\\.', '\\.local',
  '192\\.168\\.', '10\\.0\\.', '172\\.(1[6-9]|2[0-9]|3[01])\\.'
];

// Known vendors we can detect
const VENDOR_PATTERNS: Record<string, RegExp[]> = {
  salesforce: [/salesforce|force\.com|sobject/i],
  hubspot: [/hubspot|hubapi/i],
  stripe: [/stripe/i],
  snowflake: [/snowflake/i],
  zendesk: [/zendesk/i],
  slack: [/slack(?:\.com|api)/i],
  quickbooks: [/quickbooks|intuit/i],
  shopify: [/shopify/i],
  servicenow: [/servicenow|service-now/i],
  microsoft365: [/graph\.microsoft|office365/i],
  openai: [/openai/i],
  anthropic: [/anthropic/i]
};

interface DetectionContext {
  allCode: string;
  configContent: string;
  packageJson: any;
  fileList: string[];
}

/**
 * Detect server profile from a server directory
 */
export async function detectServerProfile(serverPath: string): Promise<ServerProfile> {
  const profile = createEmptyProfile();
  const patterns: string[] = [];
  const vendors: string[] = [];

  // Gather context
  const context = await gatherContext(serverPath);

  // Run all detectors
  detectExternalAPIs(context, profile, patterns, vendors);
  detectInternalAPIs(context, profile, patterns);
  detectOAuth(context, profile, patterns);
  detectWebhooks(context, profile, patterns);
  detectDatabaseWrites(context, profile, patterns);
  detectMessageQueue(context, profile, patterns);
  detectMCPServer(context, profile, patterns);
  detectHTTPLayer(context, profile, patterns);
  detectWebSocketLayer(context, profile, patterns);
  detectInterLock(context, profile, patterns);

  // Set detected patterns and vendors
  profile.detectedPatterns = [...new Set(patterns)];
  profile.detectedVendors = [...new Set(vendors)];

  // Classify server type
  profile.type = classifyServerType(profile);

  // Calculate confidence
  profile.confidence = calculateConfidence(profile.detectedPatterns);

  return profile;
}

/**
 * Gather all context needed for detection
 */
async function gatherContext(serverPath: string): Promise<DetectionContext> {
  // Default ignore patterns
  const ignorePatterns = [
    '**/node_modules/**',
    '**/dist/**',
    '**/build/**',
    '**/*.test.*',
    '**/*.spec.*'
  ];

  // Read config for additional exclusions (profiling.exclude_paths)
  try {
    const configPath = join(serverPath, 'config', 'interlock.json');
    const configData = JSON.parse(readFileSync(configPath, 'utf-8'));
    if (configData.profiling?.exclude_paths && Array.isArray(configData.profiling.exclude_paths)) {
      ignorePatterns.push(...configData.profiling.exclude_paths);
    }
  } catch {
    // No config or no profiling section - use defaults only
  }

  // Get all source files
  const patterns = ['**/*.ts', '**/*.js', '**/*.tsx', '**/*.jsx'];
  const files: string[] = [];

  for (const pattern of patterns) {
    const matches = await glob(pattern, {
      cwd: serverPath,
      ignore: ignorePatterns
    });
    files.push(...matches.map(f => join(serverPath, f)));
  }

  // Read all code into one string for pattern matching
  let allCode = '';
  for (const file of files) {
    try {
      allCode += readFileSync(file, 'utf-8') + '\n';
    } catch {
      // Skip unreadable files
    }
  }

  // Read config file if exists
  let configContent = '';
  try {
    const configPath = join(serverPath, 'config', 'interlock.json');
    configContent = readFileSync(configPath, 'utf-8');
  } catch {
    // No config file
  }

  // Read package.json
  let packageJson = {};
  try {
    const pkgPath = join(serverPath, 'package.json');
    packageJson = JSON.parse(readFileSync(pkgPath, 'utf-8'));
  } catch {
    // No package.json
  }

  return { allCode, configContent, packageJson, fileList: files };
}

/**
 * Detect external API calls
 */
function detectExternalAPIs(
  context: DetectionContext,
  profile: ServerProfile,
  patterns: string[],
  vendors: string[]
): void {
  const { allCode } = context;

  // Check for HTTP client libraries
  const hasHttpClient = /fetch\s*\(|axios\.|got\(|request\(|http\.request|https\.request/i.test(allCode);

  if (hasHttpClient) {
    // Check if URLs are external
    for (const domain of EXTERNAL_DOMAINS) {
      const domainRegex = new RegExp(domain, 'i');
      if (domainRegex.test(allCode)) {
        profile.hasExternalAPIs = true;
        patterns.push(`external-api:${domain}`);
      }
    }

    // Check if calls are NOT to internal addresses
    const hasExternalUrl = EXTERNAL_DOMAINS.some(d => new RegExp(d, 'i').test(allCode));
    const hasOnlyInternalUrl = INTERNAL_PATTERNS.every(p => new RegExp(p, 'i').test(allCode)) &&
                               !hasExternalUrl;

    if (hasHttpClient && hasExternalUrl && !hasOnlyInternalUrl) {
      profile.hasExternalAPIs = true;
      patterns.push('external-http-calls');
    }

    // Detect specific vendors
    for (const [vendor, regexes] of Object.entries(VENDOR_PATTERNS)) {
      for (const regex of regexes) {
        if (regex.test(allCode)) {
          vendors.push(vendor);
          patterns.push(`vendor:${vendor}`);
        }
      }
    }
  }
}

/**
 * Detect internal API calls
 */
function detectInternalAPIs(
  context: DetectionContext,
  profile: ServerProfile,
  patterns: string[]
): void {
  const { allCode } = context;

  const hasHttpClient = /fetch\s*\(|axios\.|got\(|request\(|http\.request|https\.request/i.test(allCode);

  if (hasHttpClient) {
    for (const pattern of INTERNAL_PATTERNS) {
      const internalRegex = new RegExp(pattern, 'i');
      if (internalRegex.test(allCode)) {
        profile.hasInternalAPIs = true;
        patterns.push('internal-api-calls');
        break;
      }
    }
  }
}

/**
 * Detect OAuth usage
 */
function detectOAuth(
  context: DetectionContext,
  profile: ServerProfile,
  patterns: string[]
): void {
  const { allCode } = context;

  const oauthPatterns = [
    /oauth/i,
    /refresh.?token/i,
    /access.?token/i,
    /authorization.*bearer/i,
    /client.?id.*client.?secret/i,
    /grant.?type/i
  ];

  for (const pattern of oauthPatterns) {
    if (pattern.test(allCode)) {
      profile.hasOAuth = true;
      patterns.push('oauth-pattern');
      break;
    }
  }
}

/**
 * Detect webhook handling
 */
function detectWebhooks(
  context: DetectionContext,
  profile: ServerProfile,
  patterns: string[]
): void {
  const { allCode } = context;

  const webhookPatterns = [
    /webhook/i,
    /signature.*verification/i,
    /x-.*-signature/i,
    /hmac.*verify/i,
    /verify.*webhook/i,
    /webhook.*secret/i
  ];

  for (const pattern of webhookPatterns) {
    if (pattern.test(allCode)) {
      profile.hasWebhooks = true;
      patterns.push('webhook-handler');
      break;
    }
  }
}

/**
 * Detect database write operations
 */
function detectDatabaseWrites(
  context: DetectionContext,
  profile: ServerProfile,
  patterns: string[]
): void {
  const { allCode } = context;

  const dbWritePatterns = [
    /\.insert\s*\(/i,
    /\.update\s*\(/i,
    /\.delete\s*\(/i,
    /\.save\s*\(/i,
    /\.create\s*\(/i,
    /exec\s*\(.*INSERT/i,
    /exec\s*\(.*UPDATE/i,
    /exec\s*\(.*DELETE/i,
    /db\.run\s*\(/i,
    /\.query\s*\(.*INSERT/i,
    /\.query\s*\(.*UPDATE/i
  ];

  for (const pattern of dbWritePatterns) {
    if (pattern.test(allCode)) {
      profile.hasDatabaseWrites = true;
      patterns.push('database-writes');
      break;
    }
  }
}

/**
 * Detect message queue usage
 */
function detectMessageQueue(
  context: DetectionContext,
  profile: ServerProfile,
  patterns: string[]
): void {
  const { allCode, packageJson } = context;

  const mqPatterns = [
    /rabbitmq|amqp/i,
    /kafka/i,
    /redis.*publish|redis.*subscribe/i,
    /bullmq|bull\./i,
    /sqs|sns/i,
    /message.?queue/i,
    /\.sendMessage\s*\(/i,
    /\.receiveMessage\s*\(/i
  ];

  for (const pattern of mqPatterns) {
    if (pattern.test(allCode)) {
      profile.hasMessageQueue = true;
      patterns.push('message-queue');
      break;
    }
  }

  // Check dependencies
  const deps = { ...(packageJson.dependencies || {}), ...(packageJson.devDependencies || {}) };
  const mqDeps = ['amqplib', 'kafkajs', 'bullmq', 'bull', '@aws-sdk/client-sqs'];
  for (const dep of mqDeps) {
    if (dep in deps) {
      profile.hasMessageQueue = true;
      patterns.push(`mq-dep:${dep}`);
    }
  }
}

/**
 * Detect MCP server patterns
 */
function detectMCPServer(
  context: DetectionContext,
  profile: ServerProfile,
  patterns: string[]
): void {
  const { allCode, packageJson } = context;

  const mcpPatterns = [
    /StdioServerTransport/i,
    /@modelcontextprotocol/i,
    /McpServer/i,
    /mcp\.Server/i,
    /registerTools/i
  ];

  for (const pattern of mcpPatterns) {
    if (pattern.test(allCode)) {
      profile.isMCPServer = true;
      patterns.push('mcp-server');
      break;
    }
  }

  // Check dependencies
  const deps = { ...(packageJson.dependencies || {}), ...(packageJson.devDependencies || {}) };
  if ('@modelcontextprotocol/sdk' in deps) {
    profile.isMCPServer = true;
    patterns.push('mcp-sdk-dep');
  }
}

/**
 * Detect HTTP server layer
 */
function detectHTTPLayer(
  context: DetectionContext,
  profile: ServerProfile,
  patterns: string[]
): void {
  const { allCode, packageJson } = context;

  const httpPatterns = [
    /express\s*\(\)/i,
    /app\.listen/i,
    /http\.createServer/i,
    /https\.createServer/i,
    /fastify/i,
    /koa/i,
    /hapi/i,
    /app\.get\s*\(/i,
    /app\.post\s*\(/i,
    /router\.get/i,
    /router\.post/i
  ];

  for (const pattern of httpPatterns) {
    if (pattern.test(allCode)) {
      profile.hasHTTPLayer = true;
      patterns.push('http-server');
      break;
    }
  }

  // Check dependencies
  const deps = { ...(packageJson.dependencies || {}), ...(packageJson.devDependencies || {}) };
  const httpDeps = ['express', 'fastify', 'koa', '@hapi/hapi'];
  for (const dep of httpDeps) {
    if (dep in deps) {
      profile.hasHTTPLayer = true;
      patterns.push(`http-dep:${dep}`);
    }
  }
}

/**
 * Detect WebSocket layer
 */
function detectWebSocketLayer(
  context: DetectionContext,
  profile: ServerProfile,
  patterns: string[]
): void {
  const { allCode, packageJson } = context;

  const wsPatterns = [
    /WebSocketServer/i,
    /ws\.Server/i,
    /socket\.io/i,
    /wss\.on/i,
    /websocket/i
  ];

  for (const pattern of wsPatterns) {
    if (pattern.test(allCode)) {
      profile.hasWebSocketLayer = true;
      patterns.push('websocket-server');
      break;
    }
  }

  // Check dependencies
  const deps = { ...(packageJson.dependencies || {}), ...(packageJson.devDependencies || {}) };
  if ('ws' in deps || 'socket.io' in deps) {
    profile.hasWebSocketLayer = true;
    patterns.push('ws-dep');
  }
}

/**
 * Detect InterLock mesh usage
 */
function detectInterLock(
  context: DetectionContext,
  profile: ServerProfile,
  patterns: string[]
): void {
  const { allCode, configContent } = context;

  const interlockPatterns = [
    /interlock/i,
    /InterlockSocket/i,
    /dgram/i,
    /udp.*socket/i,
    /tumbler/i
  ];

  for (const pattern of interlockPatterns) {
    if (pattern.test(allCode) || pattern.test(configContent)) {
      profile.hasInterLock = true;
      patterns.push('interlock-mesh');
      break;
    }
  }
}

/**
 * Quick profile detection from a single code string (for testing)
 */
export function detectProfileFromCode(code: string): ServerProfile {
  const profile = createEmptyProfile();
  const patterns: string[] = [];
  const vendors: string[] = [];

  const context: DetectionContext = {
    allCode: code,
    configContent: '',
    packageJson: {},
    fileList: []
  };

  detectExternalAPIs(context, profile, patterns, vendors);
  detectInternalAPIs(context, profile, patterns);
  detectOAuth(context, profile, patterns);
  detectWebhooks(context, profile, patterns);
  detectDatabaseWrites(context, profile, patterns);
  detectMessageQueue(context, profile, patterns);
  detectMCPServer(context, profile, patterns);
  detectHTTPLayer(context, profile, patterns);
  detectWebSocketLayer(context, profile, patterns);
  detectInterLock(context, profile, patterns);

  profile.detectedPatterns = [...new Set(patterns)];
  profile.detectedVendors = [...new Set(vendors)];
  profile.type = classifyServerType(profile);
  profile.confidence = calculateConfidence(profile.detectedPatterns);

  return profile;
}
