/**
 * Server Profile Types and Detection
 *
 * Enables context-aware rule application by detecting what type of server
 * is being inspected and what capabilities it has.
 *
 * Based on research finding: Regex-based detection has 15-40% FP rate.
 * Server profiling eliminates inapplicable rules.
 */

export type ServerType =
  | 'api-consumer'      // Makes outbound API calls to external services
  | 'api-provider'      // Exposes HTTP endpoints for others to consume
  | 'passive-observer'  // Monitors/observes without external calls
  | 'internal'          // Internal service, no external dependencies
  | 'hybrid';           // Multiple roles (e.g., both consumes and provides APIs)

export interface ServerProfile {
  // Server classification
  type: ServerType;

  // Capability flags (detected from code)
  hasExternalAPIs: boolean;      // Makes outbound HTTP/fetch calls to external services
  hasInternalAPIs: boolean;      // Makes calls to internal services (localhost, etc.)
  hasOAuth: boolean;             // Uses OAuth tokens
  hasWebhooks: boolean;          // Receives or sends webhooks
  hasDatabaseWrites: boolean;    // Writes to DB (needs idempotency considerations)
  hasMessageQueue: boolean;      // Uses message queues (needs DLQ)

  // MCP-specific flags
  isMCPServer: boolean;          // Has MCP stdio transport
  hasHTTPLayer: boolean;         // Exposes HTTP endpoints
  hasWebSocketLayer: boolean;    // Exposes WebSocket
  hasInterLock: boolean;         // Uses UDP mesh protocol

  // Detection confidence
  confidence: number;            // 0-1 how confident we are in the profile
  detectedPatterns: string[];    // What patterns we found

  // Detection metadata
  detectedVendors: string[];     // External vendor APIs detected
  detectedAt: string;            // ISO timestamp
}

/**
 * Rule categories and their applicability conditions
 */
export interface RuleApplicability {
  category: string;
  requires: Partial<ServerProfile>;
  description: string;
}

/**
 * Define which profile flags each rule category requires
 */
export const RULE_APPLICABILITY: RuleApplicability[] = [
  // Rate limiting (outbound)
  {
    category: 'circuit-breaker',
    requires: { hasExternalAPIs: true },
    description: 'Circuit breaker only needed for external API calls'
  },
  {
    category: 'retry-logic',
    requires: { hasExternalAPIs: true },
    description: 'Retry logic only needed for external API calls'
  },
  {
    category: 'timeout-handling',
    requires: { hasExternalAPIs: true },
    description: 'Timeout handling only needed for external API calls'
  },
  {
    category: 'rate-limit-outbound',
    requires: { hasExternalAPIs: true },
    description: 'Outbound rate limiting only needed for external API calls'
  },
  {
    category: 'exponential-backoff',
    requires: { hasExternalAPIs: true },
    description: 'Exponential backoff only needed for external API calls'
  },
  {
    category: 'jitter',
    requires: { hasExternalAPIs: true },
    description: 'Jitter only needed for external API retry logic'
  },

  // OAuth/Auth
  {
    category: 'oauth-token-refresh',
    requires: { hasOAuth: true },
    description: 'Token refresh only needed for OAuth integrations'
  },
  {
    category: 'token-expiry',
    requires: { hasOAuth: true },
    description: 'Token expiry handling only needed for OAuth integrations'
  },

  // Webhooks
  {
    category: 'webhook-signature',
    requires: { hasWebhooks: true },
    description: 'Webhook signature validation only for webhook receivers'
  },
  {
    category: 'replay-protection',
    requires: { hasWebhooks: true },
    description: 'Replay protection only for webhook receivers'
  },

  // Data integrity
  {
    category: 'idempotency-keys',
    requires: { hasDatabaseWrites: true, hasExternalAPIs: true },
    description: 'Idempotency needed when combining DB writes with external APIs'
  },
  {
    category: 'dead-letter-queue',
    requires: { hasMessageQueue: true },
    description: 'DLQ only needed for message queue processing'
  },

  // MCP-specific
  {
    category: 'mcp-health-checks',
    requires: { isMCPServer: true },
    description: 'MCP health checks for MCP servers'
  },
  {
    category: 'mcp-error-codes',
    requires: { isMCPServer: true },
    description: 'JSON-RPC error codes for MCP servers'
  },
  {
    category: 'mcp-logging',
    requires: { isMCPServer: true },
    description: 'Structured logging for MCP servers'
  },

  // HTTP layer
  {
    category: 'rate-limit-inbound',
    requires: { hasHTTPLayer: true },
    description: 'Inbound rate limiting for HTTP servers'
  },
  {
    category: 'request-id-tracing',
    requires: { hasHTTPLayer: true },
    description: 'Request ID tracing for HTTP servers'
  },
  {
    category: 'graceful-shutdown',
    requires: { hasHTTPLayer: true },
    description: 'Graceful shutdown for HTTP servers'
  },
  {
    category: 'error-classification',
    requires: { hasHTTPLayer: true },
    description: 'Error classification for HTTP servers'
  }
];

/**
 * Create an empty server profile with defaults
 */
export function createEmptyProfile(): ServerProfile {
  return {
    type: 'internal',
    hasExternalAPIs: false,
    hasInternalAPIs: false,
    hasOAuth: false,
    hasWebhooks: false,
    hasDatabaseWrites: false,
    hasMessageQueue: false,
    isMCPServer: false,
    hasHTTPLayer: false,
    hasWebSocketLayer: false,
    hasInterLock: false,
    confidence: 0,
    detectedPatterns: [],
    detectedVendors: [],
    detectedAt: new Date().toISOString()
  };
}

/**
 * Determine server type based on detected capabilities
 */
export function classifyServerType(profile: Omit<ServerProfile, 'type'>): ServerType {
  const { hasExternalAPIs, hasHTTPLayer, isMCPServer } = profile;

  // Has both external API calls and HTTP layer = hybrid
  if (hasExternalAPIs && hasHTTPLayer) {
    return 'hybrid';
  }

  // Makes external API calls = api-consumer
  if (hasExternalAPIs) {
    return 'api-consumer';
  }

  // Exposes HTTP endpoints = api-provider
  if (hasHTTPLayer) {
    return 'api-provider';
  }

  // MCP server without external APIs = passive-observer
  if (isMCPServer && !hasExternalAPIs) {
    return 'passive-observer';
  }

  // Default to internal
  return 'internal';
}

/**
 * Calculate confidence score based on detected patterns
 */
export function calculateConfidence(detectedPatterns: string[]): number {
  // More patterns = higher confidence
  const patternCount = detectedPatterns.length;

  if (patternCount === 0) return 0.1;
  if (patternCount <= 2) return 0.3;
  if (patternCount <= 5) return 0.6;
  if (patternCount <= 10) return 0.8;
  return 0.95;
}
