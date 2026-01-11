/**
 * Rate Limiting Rules - Research-backed from 7 Perplexity documents
 *
 * Rate limiting accounts for 35-40% of API failures
 * Mean time to detect: 15 minutes
 * Mean time to resolve: 2 hours
 * Revenue impact: $5K-$50K per incident
 */

export interface RateLimitConfig {
  limit: number;
  window_ms: number;
  type: 'leaky_bucket' | 'sliding_window' | 'token_bucket' | 'fixed_window' | 'tier_based' | 'multi_layer' | 'user_defined';
  burst_limit?: number;
  concurrent_limit?: number;
  daily_limit?: number;
  deep_pagination_limit?: number;
}

export const VENDOR_RATE_LIMITS: Record<string, RateLimitConfig> = {
  salesforce: {
    limit: 100,
    window_ms: 20000, // 100 requests per 20 seconds
    type: 'leaky_bucket',
    concurrent_limit: 25,
    daily_limit: 1000000 // Enterprise tier, developer is 5000/day
  },
  hubspot: {
    limit: 190,
    window_ms: 10000, // 190 requests per 10 seconds (NOT 100/min!)
    type: 'sliding_window',
    daily_limit: 500000
  },
  stripe: {
    limit: 100,
    window_ms: 1000, // 100 requests per second
    type: 'token_bucket',
    burst_limit: 150
  },
  snowflake: {
    limit: 30,
    window_ms: 60000, // 30 requests per minute
    type: 'fixed_window'
  },
  zendesk: {
    limit: 700,
    window_ms: 60000, // 700 requests per minute
    type: 'sliding_window',
    deep_pagination_limit: 10 // Deep pagination throttled to 10 req/min
  },
  slack: {
    limit: 50, // Tier 3 default
    window_ms: 60000,
    type: 'tier_based'
    // Note: Non-Marketplace apps limited to 1 req/min!
  },
  quickbooks: {
    limit: 500,
    window_ms: 60000, // 500 requests per minute
    type: 'sliding_window',
    concurrent_limit: 10 // Max 10 concurrent requests
  },
  shopify: {
    limit: 4,
    window_ms: 1000, // 4 requests per second (REST leaky bucket)
    type: 'leaky_bucket'
    // GraphQL uses point system - costs unpredictable
  },
  servicenow: {
    limit: 0, // User-defined - no default!
    window_ms: 0,
    type: 'user_defined'
    // Must be configured by admin
  },
  microsoft365: {
    limit: 130000,
    window_ms: 10000, // 130K requests per 10 seconds
    type: 'multi_layer'
    // Different services have different limits!
  }
};

export interface RateLimitRule {
  id: string;
  name: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  check: (code: string, vendor?: string) => RateLimitViolation[];
}

export interface RateLimitViolation {
  rule_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  location?: string;
  issue: string;
  remedy: string;
  auto_fixable: boolean;
}

export const RATE_LIMIT_RULES: RateLimitRule[] = [
  {
    id: 'rl-001',
    name: 'No Rate Limiter',
    description: 'Code must implement rate limiting for API calls',
    severity: 'CRITICAL',
    check: (code: string, vendor?: string): RateLimitViolation[] => {
      const violations: RateLimitViolation[] = [];

      // Check for rate limiting patterns
      const hasRateLimiter = /rate[_-]?limit|throttle|backoff|delay|queue/i.test(code);
      const hasApiCalls = /fetch|axios|http|request|api/i.test(code);

      if (hasApiCalls && !hasRateLimiter) {
        violations.push({
          rule_id: 'rl-001',
          severity: 'CRITICAL',
          issue: 'No rate limiting implementation detected',
          remedy: vendor
            ? `Add rate limiter with ${VENDOR_RATE_LIMITS[vendor]?.limit || 100} req/${VENDOR_RATE_LIMITS[vendor]?.window_ms || 1000}ms for ${vendor}`
            : 'Add rate limiting with exponential backoff',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'rl-002',
    name: 'Wrong Rate Limit Values',
    description: 'Rate limit values must match vendor specifications',
    severity: 'HIGH',
    check: (code: string, vendor?: string): RateLimitViolation[] => {
      const violations: RateLimitViolation[] = [];

      if (!vendor || !VENDOR_RATE_LIMITS[vendor]) return violations;

      const config = VENDOR_RATE_LIMITS[vendor];

      // Look for rate limit values in code
      const limitMatch = code.match(/limit[:\s=]+(\d+)/i);
      const windowMatch = code.match(/window[:\s=]+(\d+)/i);

      if (limitMatch) {
        const codeLimit = parseInt(limitMatch[1]);
        if (codeLimit > config.limit) {
          violations.push({
            rule_id: 'rl-002',
            severity: 'HIGH',
            location: `Rate limit value: ${codeLimit}`,
            issue: `Rate limit ${codeLimit} exceeds ${vendor} limit of ${config.limit}`,
            remedy: `Change rate limit to ${config.limit} requests per ${config.window_ms}ms`,
            auto_fixable: true
          });
        }
      }

      return violations;
    }
  },
  {
    id: 'rl-003',
    name: 'No Exponential Backoff',
    description: 'Must implement exponential backoff for retries',
    severity: 'CRITICAL',
    check: (code: string): RateLimitViolation[] => {
      const violations: RateLimitViolation[] = [];

      const hasRetry = /retry|attempt|retries/i.test(code);
      const hasExponentialBackoff = /exponential|backoff|\*\s*2|\*=\s*2|Math\.pow.*2|2\s*\*\*/i.test(code);

      if (hasRetry && !hasExponentialBackoff) {
        violations.push({
          rule_id: 'rl-003',
          severity: 'CRITICAL',
          issue: 'Retry logic without exponential backoff detected',
          remedy: 'Implement exponential backoff: delay = base * (2 ** attempt)',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'rl-004',
    name: 'No Jitter',
    description: 'Backoff must include jitter to prevent thundering herd',
    severity: 'HIGH',
    check: (code: string): RateLimitViolation[] => {
      const violations: RateLimitViolation[] = [];

      const hasBackoff = /backoff|delay.*retry/i.test(code);
      const hasJitter = /jitter|random|Math\.random/i.test(code);

      if (hasBackoff && !hasJitter) {
        violations.push({
          rule_id: 'rl-004',
          severity: 'HIGH',
          issue: 'Backoff without jitter detected - risk of thundering herd',
          remedy: 'Add ±30% jitter: delay = delay * (1 + (Math.random() * 0.6 - 0.3))',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'rl-005',
    name: 'No Circuit Breaker',
    description: 'Must implement circuit breaker pattern',
    severity: 'CRITICAL',
    check: (code: string): RateLimitViolation[] => {
      const violations: RateLimitViolation[] = [];

      const hasApiCalls = /fetch|axios|http|request|api/i.test(code);
      const hasCircuitBreaker = /circuit[_-]?breaker|OPEN|CLOSED|HALF[_-]?OPEN/i.test(code);

      if (hasApiCalls && !hasCircuitBreaker) {
        violations.push({
          rule_id: 'rl-005',
          severity: 'CRITICAL',
          issue: 'No circuit breaker pattern detected',
          remedy: 'Implement circuit breaker: CLOSED → OPEN (5 failures) → HALF-OPEN (60s) → test → CLOSED/OPEN',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'rl-006',
    name: 'No Retry-After Header Handling',
    description: 'Must respect Retry-After header from 429 responses',
    severity: 'MEDIUM',
    check: (code: string): RateLimitViolation[] => {
      const violations: RateLimitViolation[] = [];

      const handles429 = /429|too.?many.?requests|rate.?limit/i.test(code);
      const readsRetryAfter = /retry-after|retryafter/i.test(code);

      if (handles429 && !readsRetryAfter) {
        violations.push({
          rule_id: 'rl-006',
          severity: 'MEDIUM',
          issue: 'Handles 429 but does not read Retry-After header',
          remedy: 'Read and respect Retry-After header value when present',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'rl-007',
    name: 'ServiceNow No Rate Limit Config',
    description: 'ServiceNow requires explicit rate limit configuration',
    severity: 'HIGH',
    check: (code: string, vendor?: string): RateLimitViolation[] => {
      const violations: RateLimitViolation[] = [];

      if (vendor !== 'servicenow') return violations;

      const hasRateLimitConfig = /rate[_-]?limit.*config|config.*rate[_-]?limit/i.test(code);

      if (!hasRateLimitConfig) {
        violations.push({
          rule_id: 'rl-007',
          severity: 'HIGH',
          issue: 'ServiceNow has no default rate limits - must be configured',
          remedy: 'Add explicit rate limit configuration for ServiceNow instance',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'rl-008',
    name: 'Shopify GraphQL Points Not Tracked',
    description: 'Shopify GraphQL requires point tracking',
    severity: 'HIGH',
    check: (code: string, vendor?: string): RateLimitViolation[] => {
      const violations: RateLimitViolation[] = [];

      if (vendor !== 'shopify') return violations;

      const usesGraphQL = /graphql|query\s*{|mutation\s*{/i.test(code);
      const tracksPoints = /point|cost|throttle/i.test(code);

      if (usesGraphQL && !tracksPoints) {
        violations.push({
          rule_id: 'rl-008',
          severity: 'HIGH',
          issue: 'Shopify GraphQL detected but no point tracking',
          remedy: 'Track GraphQL query cost points - costs vary by query complexity',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'rl-009',
    name: 'Zendesk Deep Pagination',
    description: 'Zendesk deep pagination is severely throttled',
    severity: 'MEDIUM',
    check: (code: string, vendor?: string): RateLimitViolation[] => {
      const violations: RateLimitViolation[] = [];

      if (vendor !== 'zendesk') return violations;

      const usesPagination = /page|offset|cursor|next/i.test(code);
      const hasDeepPaginationHandling = /deep.?pagination|pagination.?limit|10.?req/i.test(code);

      if (usesPagination && !hasDeepPaginationHandling) {
        violations.push({
          rule_id: 'rl-009',
          severity: 'MEDIUM',
          issue: 'Zendesk deep pagination throttled to 10 req/min - not handled',
          remedy: 'Add special handling for deep pagination (>1000 records)',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'rl-010',
    name: 'Microsoft 365 Multi-Layer Throttling',
    description: 'Microsoft 365 has multi-layer throttling per service',
    severity: 'MEDIUM',
    check: (code: string, vendor?: string): RateLimitViolation[] => {
      const violations: RateLimitViolation[] = [];

      if (vendor !== 'microsoft365') return violations;

      const hasMultiLayerHandling = /service.?specific|multi.?layer|teams.?limit|outlook.?limit/i.test(code);

      if (!hasMultiLayerHandling) {
        violations.push({
          rule_id: 'rl-010',
          severity: 'MEDIUM',
          issue: 'Microsoft 365 has multi-layer throttling - not detected',
          remedy: 'Implement service-specific rate limiting (Teams, Outlook, etc. have different limits)',
          auto_fixable: false
        });
      }

      return violations;
    }
  }
];

export function checkRateLimitRules(code: string, vendor?: string): RateLimitViolation[] {
  const violations: RateLimitViolation[] = [];

  for (const rule of RATE_LIMIT_RULES) {
    violations.push(...rule.check(code, vendor));
  }

  return violations;
}

export function getVendorRateLimitConfig(vendor: string): RateLimitConfig | null {
  return VENDOR_RATE_LIMITS[vendor.toLowerCase()] || null;
}
