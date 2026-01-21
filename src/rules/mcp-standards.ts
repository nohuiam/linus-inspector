/**
 * MCP Quality Standards Rules
 *
 * Based on 2025 MCP specification research (Document 5).
 * These rules apply ONLY to MCP servers (profile.isMCPServer === true).
 *
 * Categories:
 * - Health endpoints (/health, /health/ready, /health/detailed)
 * - JSON-RPC error codes (-32700 to -32603)
 * - Rate limiting headers (X-RateLimit-*)
 * - Structured logging with correlation IDs
 */

export interface MCPStandardRule {
  id: string;
  name: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: 'mcp-health-checks' | 'mcp-error-codes' | 'mcp-rate-limit' | 'mcp-logging';
  check: (code: string) => MCPViolation[];
}

export interface MCPViolation {
  rule_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  location?: string;
  issue: string;
  remedy: string;
  auto_fixable: boolean;
  fix_template?: string;
}

/**
 * MCP Quality Standard Rules
 */
export const MCP_STANDARD_RULES: MCPStandardRule[] = [
  // Health Check Rules
  {
    id: 'mcp-001',
    name: 'MCP Health Endpoint',
    description: 'MCP servers must have a /health endpoint for liveness checks',
    severity: 'HIGH',
    category: 'mcp-health-checks',
    check: (code: string): MCPViolation[] => {
      const violations: MCPViolation[] = [];

      // Check for health endpoint
      const hasHealthEndpoint = /['"](\/health|\/api\/health)['"]/i.test(code) ||
                                /\.get\s*\(\s*['"]\/?health/i.test(code);

      // Must have HTTP layer for health endpoints
      const hasHTTPLayer = /express|fastify|koa|app\.listen|http\.createServer/i.test(code);

      if (hasHTTPLayer && !hasHealthEndpoint) {
        violations.push({
          rule_id: 'mcp-001',
          severity: 'HIGH',
          issue: 'MCP server with HTTP layer missing /health endpoint',
          remedy: 'Add /health endpoint for liveness checks',
          auto_fixable: true,
          fix_template: `app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: process.env.npm_package_name || 'unknown',
    uptime: process.uptime()
  });
});`
        });
      }

      return violations;
    }
  },
  {
    id: 'mcp-002',
    name: 'MCP Readiness Endpoint',
    description: 'MCP servers should have a /health/ready endpoint for readiness checks',
    severity: 'MEDIUM',
    category: 'mcp-health-checks',
    check: (code: string): MCPViolation[] => {
      const violations: MCPViolation[] = [];

      const hasHTTPLayer = /express|fastify|koa|app\.listen|http\.createServer/i.test(code);
      const hasReadyEndpoint = /['"](\/health\/ready|\/ready)['"]/i.test(code);

      if (hasHTTPLayer && !hasReadyEndpoint) {
        violations.push({
          rule_id: 'mcp-002',
          severity: 'MEDIUM',
          issue: 'Missing /health/ready endpoint for readiness checks',
          remedy: 'Add /health/ready endpoint for Kubernetes/load balancer routing',
          auto_fixable: true,
          fix_template: `app.get('/health/ready', (req, res) => {
  // Check if all dependencies are ready
  const ready = checkDependencies();
  res.status(ready ? 200 : 503).json({
    ready,
    timestamp: new Date().toISOString()
  });
});`
        });
      }

      return violations;
    }
  },
  {
    id: 'mcp-003',
    name: 'MCP Detailed Health Endpoint',
    description: 'MCP servers should have a /health/detailed endpoint for debugging',
    severity: 'LOW',
    category: 'mcp-health-checks',
    check: (code: string): MCPViolation[] => {
      const violations: MCPViolation[] = [];

      const hasHTTPLayer = /express|fastify|koa|app\.listen|http\.createServer/i.test(code);
      const hasDetailedEndpoint = /['"](\/health\/detailed|\/health\/detail)['"]/i.test(code);

      if (hasHTTPLayer && !hasDetailedEndpoint) {
        violations.push({
          rule_id: 'mcp-003',
          severity: 'LOW',
          issue: 'Missing /health/detailed endpoint for debugging',
          remedy: 'Add /health/detailed endpoint for detailed diagnostics',
          auto_fixable: true
        });
      }

      return violations;
    }
  },

  // Error Code Rules
  {
    id: 'mcp-004',
    name: 'JSON-RPC Error Codes',
    description: 'MCP servers should use standard JSON-RPC error codes',
    severity: 'MEDIUM',
    category: 'mcp-error-codes',
    check: (code: string): MCPViolation[] => {
      const violations: MCPViolation[] = [];

      // Check if error responses use non-standard codes
      const hasCustomErrorCode = /error.*code.*[^-]32[0-9]{3}/.test(code);
      const hasStandardCodes = /-32700|-32600|-32601|-32602|-32603/.test(code);

      // Only flag if using MCP patterns but not standard codes
      const usesMCPPatterns = /@modelcontextprotocol|McpServer|mcp\.Server/i.test(code);

      if (usesMCPPatterns && hasCustomErrorCode && !hasStandardCodes) {
        violations.push({
          rule_id: 'mcp-004',
          severity: 'MEDIUM',
          issue: 'Custom error codes detected - consider using standard JSON-RPC codes',
          remedy: 'Use standard codes: -32700 (parse), -32600 (invalid), -32601 (method not found), -32602 (params), -32603 (internal)',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'mcp-005',
    name: 'Error Retryability',
    description: 'Error responses should indicate if the error is retryable',
    severity: 'LOW',
    category: 'mcp-error-codes',
    check: (code: string): MCPViolation[] => {
      const violations: MCPViolation[] = [];

      // Check for error responses without retryable field
      const hasErrorResponse = /status\s*\(\s*[45]\d{2}\s*\).*json/i.test(code);
      const hasRetryable = /retryable/i.test(code);

      if (hasErrorResponse && !hasRetryable) {
        violations.push({
          rule_id: 'mcp-005',
          severity: 'LOW',
          issue: 'Error responses do not indicate retryability',
          remedy: 'Include retryable: boolean in error responses for client retry logic',
          auto_fixable: true
        });
      }

      return violations;
    }
  },

  // Rate Limiting Rules (Inbound)
  {
    id: 'mcp-006',
    name: 'Inbound Rate Limiting',
    description: 'HTTP servers should implement inbound rate limiting',
    severity: 'MEDIUM',
    category: 'mcp-rate-limit',
    check: (code: string): MCPViolation[] => {
      const violations: MCPViolation[] = [];

      const hasHTTPLayer = /express|fastify|koa|app\.listen|http\.createServer/i.test(code);
      const hasRateLimit = /rate[_-]?limit|express-rate-limit|ratelimit/i.test(code);

      if (hasHTTPLayer && !hasRateLimit) {
        violations.push({
          rule_id: 'mcp-006',
          severity: 'MEDIUM',
          issue: 'HTTP server missing inbound rate limiting',
          remedy: 'Add rate limiting middleware to protect against abuse',
          auto_fixable: true,
          fix_template: `// Add rate limiting middleware
const rateLimitMap = new Map();
const WINDOW_MS = 60000;
const MAX_REQUESTS = 100;

app.use((req, res, next) => {
  const ip = req.ip || 'unknown';
  const now = Date.now();
  let entry = rateLimitMap.get(ip);

  if (!entry || now > entry.resetTime) {
    entry = { count: 0, resetTime: now + WINDOW_MS };
    rateLimitMap.set(ip, entry);
  }

  entry.count++;

  res.setHeader('X-RateLimit-Limit', MAX_REQUESTS);
  res.setHeader('X-RateLimit-Remaining', Math.max(0, MAX_REQUESTS - entry.count));

  if (entry.count > MAX_REQUESTS) {
    return res.status(429).json({ error: 'Too Many Requests' });
  }

  next();
});`
        });
      }

      return violations;
    }
  },
  {
    id: 'mcp-007',
    name: 'Rate Limit Headers',
    description: 'Rate limited responses should include standard headers',
    severity: 'LOW',
    category: 'mcp-rate-limit',
    check: (code: string): MCPViolation[] => {
      const violations: MCPViolation[] = [];

      const has429Response = /status\s*\(\s*429\s*\)/i.test(code);
      const hasLimitHeader = /X-RateLimit-Limit/i.test(code);
      const hasRemainingHeader = /X-RateLimit-Remaining/i.test(code);

      if (has429Response && (!hasLimitHeader || !hasRemainingHeader)) {
        violations.push({
          rule_id: 'mcp-007',
          severity: 'LOW',
          issue: 'Rate limit responses missing standard headers',
          remedy: 'Add X-RateLimit-Limit, X-RateLimit-Remaining, and Retry-After headers',
          auto_fixable: true
        });
      }

      return violations;
    }
  },

  // Logging Rules
  {
    id: 'mcp-008',
    name: 'Structured Logging',
    description: 'MCP servers should use structured JSON logging',
    severity: 'LOW',
    category: 'mcp-logging',
    check: (code: string): MCPViolation[] => {
      const violations: MCPViolation[] = [];

      // Check for console.log with string template (unstructured)
      const hasUnstructuredLogs = /console\.(log|error)\s*\(\s*[`'"]/.test(code);
      const hasStructuredLogs = /console\.(log|error)\s*\(\s*JSON\.stringify|winston|pino|bunyan/i.test(code);

      // Only flag if using MCP patterns
      const usesMCPPatterns = /@modelcontextprotocol|McpServer/i.test(code);

      if (usesMCPPatterns && hasUnstructuredLogs && !hasStructuredLogs) {
        violations.push({
          rule_id: 'mcp-008',
          severity: 'LOW',
          issue: 'Unstructured logging detected - consider structured JSON logging',
          remedy: 'Use structured logging (JSON) for better log aggregation',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'mcp-009',
    name: 'Request ID Tracing',
    description: 'HTTP requests should include correlation/request IDs for tracing',
    severity: 'MEDIUM',
    category: 'mcp-logging',
    check: (code: string): MCPViolation[] => {
      const violations: MCPViolation[] = [];

      const hasHTTPLayer = /express|fastify|koa|app\.listen|http\.createServer/i.test(code);
      const hasRequestId = /requestId|request_id|correlationId|correlation_id|x-request-id/i.test(code);

      if (hasHTTPLayer && !hasRequestId) {
        violations.push({
          rule_id: 'mcp-009',
          severity: 'MEDIUM',
          issue: 'HTTP server missing request ID tracing',
          remedy: 'Add request ID middleware for distributed tracing',
          auto_fixable: true,
          fix_template: `// Add request ID middleware
app.use((req, res, next) => {
  const requestId = req.headers['x-request-id'] || crypto.randomUUID();
  req.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);
  next();
});`
        });
      }

      return violations;
    }
  },

  // Graceful Shutdown
  {
    id: 'mcp-010',
    name: 'Graceful Shutdown',
    description: 'MCP servers should implement graceful shutdown',
    severity: 'MEDIUM',
    category: 'mcp-health-checks',
    check: (code: string): MCPViolation[] => {
      const violations: MCPViolation[] = [];

      const hasHTTPLayer = /express|fastify|koa|app\.listen|http\.createServer/i.test(code);
      const hasSigintHandler = /process\.on\s*\(\s*['"]SIGINT['"]/i.test(code);
      const hasGracefulShutdown = /server\.close|\.close\s*\(\s*\)/i.test(code);

      if (hasHTTPLayer && (!hasSigintHandler || !hasGracefulShutdown)) {
        violations.push({
          rule_id: 'mcp-010',
          severity: 'MEDIUM',
          issue: 'Missing graceful shutdown handling',
          remedy: 'Implement SIGINT/SIGTERM handlers that close connections gracefully',
          auto_fixable: true,
          fix_template: `process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');

  // Stop accepting new connections
  server.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });

  // Force exit after timeout
  setTimeout(() => {
    console.log('Forced shutdown');
    process.exit(1);
  }, 5000);
});`
        });
      }

      return violations;
    }
  }
];

/**
 * Check all MCP standard rules
 */
export function checkMCPStandardRules(code: string): MCPViolation[] {
  const violations: MCPViolation[] = [];

  for (const rule of MCP_STANDARD_RULES) {
    violations.push(...rule.check(code));
  }

  return violations;
}

/**
 * Check MCP standard rules by category
 */
export function checkMCPStandardRulesByCategory(
  code: string,
  category: MCPStandardRule['category']
): MCPViolation[] {
  const violations: MCPViolation[] = [];

  for (const rule of MCP_STANDARD_RULES) {
    if (rule.category === category) {
      violations.push(...rule.check(code));
    }
  }

  return violations;
}

/**
 * Get all MCP rule IDs
 */
export function getMCPRuleIds(): string[] {
  return MCP_STANDARD_RULES.map(r => r.id);
}
