/**
 * Error Handling Rules - Research-backed from Perplexity documents
 *
 * Timeout/error failures account for 25-30% of API issues
 * Mean time to detect: 30 minutes
 * Mean time to resolve: 4 hours
 * Revenue impact: $10K-$100K per incident
 *
 * Key patterns:
 * - Exponential backoff with jitter
 * - Circuit breaker (CLOSED → OPEN → HALF-OPEN)
 * - Dead Letter Queue
 * - Retryable vs non-retryable errors
 */

export interface ErrorHandlingConfig {
  retryable_codes: number[];
  non_retryable_codes: number[];
  max_retries: number;
  backoff: {
    base_ms: number;
    max_ms: number;
    jitter_percent: number;
  };
  circuit_breaker: {
    failure_threshold: number;
    cooldown_ms: number;
    half_open_requests: number;
  };
  dead_letter_queue: {
    enabled: boolean;
    alert_threshold: number;
    retention_days: number;
    auto_replay_hours: number;
  };
}

export const DEFAULT_ERROR_CONFIG: ErrorHandlingConfig = {
  retryable_codes: [429, 500, 502, 503, 504],
  non_retryable_codes: [400, 401, 403, 404],
  max_retries: 5,
  backoff: {
    base_ms: 1000,
    max_ms: 60000,
    jitter_percent: 30
  },
  circuit_breaker: {
    failure_threshold: 5,
    cooldown_ms: 60000,
    half_open_requests: 1
  },
  dead_letter_queue: {
    enabled: true,
    alert_threshold: 100,
    retention_days: 30,
    auto_replay_hours: 24
  }
};

export interface ErrorRule {
  id: string;
  name: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  check: (code: string) => ErrorViolation[];
}

export interface ErrorViolation {
  rule_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  location?: string;
  issue: string;
  remedy: string;
  auto_fixable: boolean;
}

export const ERROR_RULES: ErrorRule[] = [
  {
    id: 'err-001',
    name: 'No 4xx Error Handlers',
    description: 'Must handle 400, 401, 403, 404 errors appropriately',
    severity: 'CRITICAL',
    check: (code: string): ErrorViolation[] => {
      const violations: ErrorViolation[] = [];

      const hasApiCalls = /fetch|axios|http|request|api/i.test(code);
      const has4xxHandling = /400|401|403|404|bad.*request|unauthorized|forbidden|not.*found/i.test(code);

      if (hasApiCalls && !has4xxHandling) {
        violations.push({
          rule_id: 'err-001',
          severity: 'CRITICAL',
          issue: 'No handlers for 4xx errors (400, 401, 403, 404)',
          remedy: 'Add handlers: 400=bad request (fix payload), 401=refresh token, 403=check permissions, 404=resource missing',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'err-002',
    name: 'No 5xx Error Handlers',
    description: 'Must handle 500, 502, 503, 504 errors with retries',
    severity: 'CRITICAL',
    check: (code: string): ErrorViolation[] => {
      const violations: ErrorViolation[] = [];

      const hasApiCalls = /fetch|axios|http|request|api/i.test(code);
      const has5xxHandling = /500|502|503|504|server.*error|bad.*gateway|unavailable|timeout/i.test(code);

      if (hasApiCalls && !has5xxHandling) {
        violations.push({
          rule_id: 'err-002',
          severity: 'CRITICAL',
          issue: 'No handlers for 5xx errors (500, 502, 503, 504)',
          remedy: 'Add retry logic with exponential backoff for 5xx errors (these are transient)',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'err-003',
    name: 'No Dead Letter Queue',
    description: 'Failed messages must go to DLQ after max retries',
    severity: 'HIGH',
    check: (code: string): ErrorViolation[] => {
      const violations: ErrorViolation[] = [];

      const hasRetries = /retry|attempt|retries/i.test(code);
      const hasDLQ = /dead[_-]?letter|dlq|failed[_-]?queue|error[_-]?queue/i.test(code);

      if (hasRetries && !hasDLQ) {
        violations.push({
          rule_id: 'err-003',
          severity: 'HIGH',
          issue: 'Retry logic without Dead Letter Queue - failed messages lost forever',
          remedy: 'Store failed messages in DLQ after 5 retries for manual review/replay',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'err-004',
    name: 'No Max Retry Limit',
    description: 'Must have maximum retry limit to prevent infinite loops',
    severity: 'CRITICAL',
    check: (code: string): ErrorViolation[] => {
      const violations: ErrorViolation[] = [];

      const hasRetries = /retry|attempt/i.test(code);
      const hasMaxRetries = /max[_-]?retr|retry.*limit|limit.*retry|\<\s*5|\<\s*3|\<\=\s*5/i.test(code);

      if (hasRetries && !hasMaxRetries) {
        violations.push({
          rule_id: 'err-004',
          severity: 'CRITICAL',
          issue: 'Retry logic without maximum retry limit - risk of infinite loop',
          remedy: 'Add max retry limit (recommended: 5 attempts)',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'err-005',
    name: 'No Timeout Configuration',
    description: 'API calls must have timeout configured',
    severity: 'HIGH',
    check: (code: string): ErrorViolation[] => {
      const violations: ErrorViolation[] = [];

      const hasApiCalls = /fetch|axios|http|request/i.test(code);
      const hasTimeout = /timeout|abort|signal/i.test(code);

      if (hasApiCalls && !hasTimeout) {
        violations.push({
          rule_id: 'err-005',
          severity: 'HIGH',
          issue: 'API calls without timeout configuration',
          remedy: 'Add timeout (recommended: 30 seconds for most APIs, 10 seconds for webhooks)',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'err-006',
    name: 'Swallowed Errors',
    description: 'Errors must not be silently swallowed',
    severity: 'HIGH',
    check: (code: string): ErrorViolation[] => {
      const violations: ErrorViolation[] = [];

      // Look for empty catch blocks (multiline-aware)
      const emptyCatch = /catch\s*\([^)]*\)\s*\{[\s\n]*\}/m;
      if (emptyCatch.test(code)) {
        violations.push({
          rule_id: 'err-006',
          severity: 'HIGH',
          issue: 'Empty catch block - errors are being swallowed silently',
          remedy: 'Log error and either rethrow, handle appropriately, or send to monitoring',
          auto_fixable: true
        });
      }

      // Look for catch that only logs (multiline-aware)
      const catchOnlyLog = /catch\s*\([^)]*\)\s*\{[\s\n]*(console\.log|logger\.info)/m;
      if (catchOnlyLog.test(code)) {
        violations.push({
          rule_id: 'err-006',
          severity: 'MEDIUM',
          issue: 'Catch block only logs - error not properly handled',
          remedy: 'After logging, either rethrow, return error state, or implement recovery',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'err-007',
    name: 'No Error Classification',
    description: 'Errors must be classified as retryable vs non-retryable',
    severity: 'MEDIUM',
    check: (code: string): ErrorViolation[] => {
      const violations: ErrorViolation[] = [];

      const hasErrorHandling = /catch|error|exception/i.test(code);
      const hasClassification = /retryable|non[_-]?retryable|transient|permanent/i.test(code);

      if (hasErrorHandling && !hasClassification) {
        violations.push({
          rule_id: 'err-007',
          severity: 'MEDIUM',
          issue: 'No error classification (retryable vs non-retryable)',
          remedy: 'Classify errors: retryable (429, 5xx) vs non-retryable (400, 401, 403, 404)',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'err-008',
    name: 'No Error Monitoring/Alerting',
    description: 'Errors must be sent to monitoring system',
    severity: 'MEDIUM',
    check: (code: string): ErrorViolation[] => {
      const violations: ErrorViolation[] = [];

      const hasErrorHandling = /catch|error|exception/i.test(code);
      const hasMonitoring = /sentry|datadog|newrelic|monitor|alert|metric|track/i.test(code);

      if (hasErrorHandling && !hasMonitoring) {
        violations.push({
          rule_id: 'err-008',
          severity: 'MEDIUM',
          issue: 'No error monitoring/alerting integration',
          remedy: 'Send errors to monitoring system (Sentry, Datadog, etc.) for observability',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'err-009',
    name: 'Retrying Non-Retryable Errors',
    description: 'Must not retry 400, 401, 403, 404 errors',
    severity: 'HIGH',
    check: (code: string): ErrorViolation[] => {
      const violations: ErrorViolation[] = [];

      // Check if retry logic includes 4xx codes
      const retries4xx = /retry.*400|retry.*401|retry.*403|retry.*404|4\d\d.*retry/i.test(code);

      if (retries4xx) {
        violations.push({
          rule_id: 'err-009',
          severity: 'HIGH',
          issue: 'Retrying 4xx errors wastes resources - these are not transient',
          remedy: 'Only retry 429 and 5xx. For 4xx: 400=fix request, 401=refresh token, 403=check perms, 404=stop',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'err-010',
    name: 'No Graceful Degradation',
    description: 'System should degrade gracefully on API failure',
    severity: 'MEDIUM',
    check: (code: string): ErrorViolation[] => {
      const violations: ErrorViolation[] = [];

      const hasApiDependency = /fetch|axios|http|api/i.test(code);
      const hasGracefulDegradation = /fallback|cache|stale|degrad|offline|default/i.test(code);

      if (hasApiDependency && !hasGracefulDegradation) {
        violations.push({
          rule_id: 'err-010',
          severity: 'MEDIUM',
          issue: 'No graceful degradation when API is unavailable',
          remedy: 'Implement fallback: serve cached data, use default values, or queue for later',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'err-011',
    name: 'No Request ID Tracking',
    description: 'Requests should include correlation ID for debugging',
    severity: 'LOW',
    check: (code: string): ErrorViolation[] => {
      const violations: ErrorViolation[] = [];

      const hasApiCalls = /fetch|axios|http|request/i.test(code);
      const hasRequestId = /request[_-]?id|correlation[_-]?id|trace[_-]?id|x-request-id/i.test(code);

      if (hasApiCalls && !hasRequestId) {
        violations.push({
          rule_id: 'err-011',
          severity: 'LOW',
          issue: 'No request/correlation ID for tracing',
          remedy: 'Add X-Request-ID header for request tracing and debugging',
          auto_fixable: true
        });
      }

      return violations;
    }
  }
];

export function checkErrorRules(code: string): ErrorViolation[] {
  const violations: ErrorViolation[] = [];

  for (const rule of ERROR_RULES) {
    violations.push(...rule.check(code));
  }

  return violations;
}

export function getDefaultErrorConfig(): ErrorHandlingConfig {
  return { ...DEFAULT_ERROR_CONFIG };
}
