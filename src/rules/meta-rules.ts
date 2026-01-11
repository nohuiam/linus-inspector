/**
 * Meta-Rules Module
 *
 * "Physician, heal thyself" - rules specific to inspectors inspecting themselves.
 * These detect hypocrisy: when an inspector doesn't follow its own advice.
 */

// ============================================================================
// Types
// ============================================================================

export interface MetaInspectionContext {
  is_inspector: boolean;
  server_type: 'inspector' | 'validator' | 'gateway' | 'other';
  inspection_categories?: string[];  // What does this inspector check?
}

export interface MetaViolation {
  rule_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  issue: string;
  remedy: string;
  irony_level: 'maximum' | 'high' | 'medium' | 'low';
  auto_fixable: boolean;
}

export interface MetaRule {
  id: string;
  name: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  irony_level: 'maximum' | 'high' | 'medium' | 'low';
  applies_to: ('inspector' | 'validator' | 'gateway' | 'other')[];
  check: (code: string, context: MetaInspectionContext) => MetaViolation[];
}

// ============================================================================
// Meta Rules
// ============================================================================

export const META_RULES: MetaRule[] = [
  {
    id: 'meta-001',
    name: 'Rate-Limit Inspector Without Rate Limiting',
    description: 'An inspector that checks for rate limiting must implement rate limiting itself',
    severity: 'CRITICAL',
    irony_level: 'maximum',
    applies_to: ['inspector'],
    check: (code: string, context: MetaInspectionContext): MetaViolation[] => {
      const violations: MetaViolation[] = [];

      // Only applies to rate-limit inspectors
      const checksRateLimiting = context.inspection_categories?.includes('rate_limiting') ||
                                  /rate[_-]?limit|throttle/i.test(code);

      if (!checksRateLimiting) return violations;

      // Check if the inspector has rate limiting on its own endpoints
      const hasHttpEndpoints = /app\.(get|post|put|delete|patch)\s*\(/i.test(code);
      const hasRateLimiter = /rateLimit|rateLimiter|createRateLimiter|express-rate-limit/i.test(code);

      if (hasHttpEndpoints && !hasRateLimiter) {
        violations.push({
          rule_id: 'meta-001',
          severity: 'CRITICAL',
          issue: 'Rate-limit inspector has HTTP endpoints but no rate limiting - maximum irony',
          remedy: 'Add rate limiting middleware to HTTP server: app.use(createRateLimiter({...}))',
          irony_level: 'maximum',
          auto_fixable: true
        });
      }

      return violations;
    }
  },

  {
    id: 'meta-002',
    name: 'Error Inspector With Poor Error Handling',
    description: 'An inspector that checks error handling must have exemplary error handling',
    severity: 'HIGH',
    irony_level: 'high',
    applies_to: ['inspector'],
    check: (code: string, context: MetaInspectionContext): MetaViolation[] => {
      const violations: MetaViolation[] = [];

      // Only applies to error-handling inspectors
      const checksErrors = context.inspection_categories?.includes('error_handling') ||
                           /error[_-]?rules|error[_-]?handling/i.test(code);

      if (!checksErrors) return violations;

      // Check for empty catch blocks
      const hasEmptyCatch = /catch\s*\([^)]*\)\s*\{[\s\n]*\}/m.test(code);
      if (hasEmptyCatch) {
        violations.push({
          rule_id: 'meta-002',
          severity: 'HIGH',
          issue: 'Error inspector has empty catch blocks - physician cannot heal thyself',
          remedy: 'Implement proper error handling in all catch blocks',
          irony_level: 'high',
          auto_fixable: false
        });
      }

      // Check for catch-only-log
      const hasCatchOnlyLog = /catch\s*\([^)]*\)\s*\{[\s\n]*(console\.(log|error)|logger\.(info|error))[^}]*\}/m.test(code);
      if (hasCatchOnlyLog) {
        violations.push({
          rule_id: 'meta-002',
          severity: 'MEDIUM',
          issue: 'Error inspector swallows errors with only logging',
          remedy: 'Re-throw errors or handle them appropriately after logging',
          irony_level: 'medium',
          auto_fixable: false
        });
      }

      return violations;
    }
  },

  {
    id: 'meta-003',
    name: 'Validator Without Input Validation',
    description: 'A validator must validate its own inputs',
    severity: 'HIGH',
    irony_level: 'high',
    applies_to: ['validator', 'inspector'],
    check: (code: string, context: MetaInspectionContext): MetaViolation[] => {
      const violations: MetaViolation[] = [];

      if (context.server_type !== 'validator' && context.server_type !== 'inspector') {
        return violations;
      }

      // Check if it has HTTP endpoints with direct req.body access without validation
      const hasDirectBodyAccess = /req\.body\.([\w]+)/g.test(code);
      const hasZodValidation = /z\.(object|string|number)|\.parse\(|\.safeParse\(/i.test(code);
      const hasOtherValidation = /validate|joi|yup|ajv/i.test(code);

      if (hasDirectBodyAccess && !hasZodValidation && !hasOtherValidation) {
        violations.push({
          rule_id: 'meta-003',
          severity: 'HIGH',
          issue: 'Validator/Inspector accesses request body without validation',
          remedy: 'Use Zod or similar to validate all request inputs',
          irony_level: 'high',
          auto_fixable: true
        });
      }

      return violations;
    }
  },

  {
    id: 'meta-004',
    name: 'Regex Rules Without Multiline Flag',
    description: 'Regex patterns checking multi-line code patterns should use multiline flag',
    severity: 'MEDIUM',
    irony_level: 'medium',
    applies_to: ['inspector', 'validator'],
    check: (code: string, _context: MetaInspectionContext): MetaViolation[] => {
      const violations: MetaViolation[] = [];

      // Find regex patterns that likely need multiline but don't have it
      // Patterns like /catch\s*\(...\)\s*{/ without /m flag
      const regexDefinitions = code.matchAll(/(?:const|let|var)\s+\w+\s*=\s*\/([^/]+)\/([gimsuvy]*)/g);

      for (const match of regexDefinitions) {
        const pattern = match[1];
        const flags = match[2];

        // Check if pattern looks like it matches code structure (braces, catches, functions)
        const looksMultiline = /\\s\*.*[{}\[\]]|catch|function|class|=>/.test(pattern);
        const hasMultilineFlag = flags.includes('m');

        if (looksMultiline && !hasMultilineFlag) {
          violations.push({
            rule_id: 'meta-004',
            severity: 'MEDIUM',
            issue: `Regex pattern appears to match multi-line code but lacks 'm' flag: /${pattern}/`,
            remedy: `Add multiline flag: /${pattern}/${flags}m`,
            irony_level: 'medium',
            auto_fixable: true
          });
        }
      }

      return violations;
    }
  },

  {
    id: 'meta-005',
    name: 'HTTP Endpoints Without Timeout',
    description: 'Async HTTP handlers should have timeout protection',
    severity: 'HIGH',
    irony_level: 'high',
    applies_to: ['inspector', 'validator', 'gateway'],
    check: (code: string, _context: MetaInspectionContext): MetaViolation[] => {
      const violations: MetaViolation[] = [];

      // Look for async POST handlers without timeout
      const hasAsyncPostHandlers = /app\.post\([^,]+,\s*async/i.test(code);
      const hasTimeoutWrapper = /withTimeout|createRequestTimeout|timeout\s*:/i.test(code);

      if (hasAsyncPostHandlers && !hasTimeoutWrapper) {
        violations.push({
          rule_id: 'meta-005',
          severity: 'HIGH',
          issue: 'Async HTTP handlers have no timeout protection - can hang indefinitely',
          remedy: 'Wrap async handlers with timeout: withTimeout(handler, 60000)',
          irony_level: 'high',
          auto_fixable: true
        });
      }

      return violations;
    }
  },

  {
    id: 'meta-006',
    name: 'Compliance Checker Not Self-Compliant',
    description: 'A compliance checker should follow its own compliance rules',
    severity: 'HIGH',
    irony_level: 'maximum',
    applies_to: ['inspector'],
    check: (code: string, context: MetaInspectionContext): MetaViolation[] => {
      const violations: MetaViolation[] = [];

      const checksCompliance = context.inspection_categories?.includes('compliance') ||
                               /compliance|hipaa|gdpr|soc2|pci/i.test(code);

      if (!checksCompliance) return violations;

      // Check for audit logging
      const hasAuditLogging = /audit[_-]?log|logAudit|createAuditEntry/i.test(code);
      if (!hasAuditLogging) {
        violations.push({
          rule_id: 'meta-006',
          severity: 'MEDIUM',
          issue: 'Compliance checker has no audit logging of its own operations',
          remedy: 'Add audit logging for inspection operations',
          irony_level: 'medium',
          auto_fixable: true
        });
      }

      return violations;
    }
  },

  {
    id: 'meta-007',
    name: 'Test Inspector Without Tests',
    description: 'An inspector that checks test coverage should have good test coverage',
    severity: 'MEDIUM',
    irony_level: 'high',
    applies_to: ['inspector'],
    check: (_code: string, context: MetaInspectionContext): MetaViolation[] => {
      const violations: MetaViolation[] = [];

      // This is checked at the project level, not code level
      // For now, just flag if it's a test inspector
      const checksTests = context.inspection_categories?.includes('test_coverage');

      if (checksTests) {
        // This would need filesystem access to check - placeholder
        violations.push({
          rule_id: 'meta-007',
          severity: 'LOW',
          issue: 'Test coverage inspector should maintain >80% coverage itself',
          remedy: 'Ensure inspector has comprehensive test coverage',
          irony_level: 'high',
          auto_fixable: false
        });
      }

      return violations;
    }
  },

  {
    id: 'meta-008',
    name: 'Security Inspector With Hardcoded Secrets',
    description: 'A security inspector must not have hardcoded secrets',
    severity: 'CRITICAL',
    irony_level: 'maximum',
    applies_to: ['inspector'],
    check: (code: string, context: MetaInspectionContext): MetaViolation[] => {
      const violations: MetaViolation[] = [];

      const checksSecurity = context.inspection_categories?.includes('security') ||
                             /security|credential|secret|api[_-]?key/i.test(code);

      if (!checksSecurity) return violations;

      // Check for hardcoded secrets
      const secretPatterns = [
        /api[_-]?key\s*[=:]\s*["'][a-zA-Z0-9]{20,}["']/i,
        /secret\s*[=:]\s*["'][a-zA-Z0-9]{16,}["']/i,
        /password\s*[=:]\s*["'][^"']{8,}["']/i,
        /sk_live_[a-zA-Z0-9]+/,
        /bearer\s+[a-zA-Z0-9]{20,}/i
      ];

      for (const pattern of secretPatterns) {
        if (pattern.test(code)) {
          violations.push({
            rule_id: 'meta-008',
            severity: 'CRITICAL',
            issue: 'Security inspector appears to have hardcoded credentials - maximum irony',
            remedy: 'Move all secrets to environment variables',
            irony_level: 'maximum',
            auto_fixable: false
          });
          break;
        }
      }

      return violations;
    }
  }
];

// ============================================================================
// Check Function
// ============================================================================

/**
 * Run all meta-rules on code
 */
export function checkMetaRules(
  code: string,
  context: MetaInspectionContext
): MetaViolation[] {
  const violations: MetaViolation[] = [];

  for (const rule of META_RULES) {
    // Check if rule applies to this server type
    if (!rule.applies_to.includes(context.server_type)) {
      continue;
    }

    const ruleViolations = rule.check(code, context);
    violations.push(...ruleViolations);
  }

  return violations;
}

/**
 * Get meta-rules summary
 */
export function getMetaRulesSummary(): {
  total: number;
  by_severity: Record<string, number>;
  by_irony: Record<string, number>;
} {
  const by_severity: Record<string, number> = {};
  const by_irony: Record<string, number> = {};

  for (const rule of META_RULES) {
    by_severity[rule.severity] = (by_severity[rule.severity] || 0) + 1;
    by_irony[rule.irony_level] = (by_irony[rule.irony_level] || 0) + 1;
  }

  return {
    total: META_RULES.length,
    by_severity,
    by_irony
  };
}
