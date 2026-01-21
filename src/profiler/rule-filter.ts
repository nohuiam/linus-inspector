/**
 * Rule Filter
 *
 * Filters rules based on server profile to eliminate false positives.
 * Only applies rules that are relevant to the server's capabilities.
 */

import {
  ServerProfile,
  RULE_APPLICABILITY,
  RuleApplicability
} from './server-profile.js';

/**
 * Rule category to applicability mapping
 * Maps rule IDs prefixes to their applicability categories
 */
const RULE_CATEGORY_MAP: Record<string, string[]> = {
  // Rate limiting rules
  'rl-001': ['rate-limit-outbound'],           // No Rate Limiter
  'rl-002': ['rate-limit-outbound'],           // Wrong Rate Limit Values
  'rl-003': ['exponential-backoff'],           // No Exponential Backoff
  'rl-004': ['jitter'],                        // No Jitter
  'rl-005': ['circuit-breaker'],               // No Circuit Breaker
  'rl-006': ['rate-limit-outbound'],           // No Retry-After Header Handling
  'rl-007': ['rate-limit-outbound'],           // ServiceNow No Rate Limit Config
  'rl-008': ['rate-limit-outbound'],           // Shopify GraphQL Points
  'rl-009': ['rate-limit-outbound'],           // Zendesk Deep Pagination
  'rl-010': ['rate-limit-outbound'],           // Microsoft 365 Multi-Layer

  // OAuth rules
  'oauth-001': ['oauth-token-refresh'],        // No Token Refresh
  'oauth-002': ['oauth-token-refresh'],        // No Token Expiry Handling
  'oauth-003': ['oauth-token-refresh'],        // Hardcoded Credentials
  'oauth-004': ['oauth-token-refresh'],        // No Secure Token Storage

  // Error handling rules - some are universal, some profile-specific
  'err-001': [],                               // Generic error handling (universal)
  'err-002': [],                               // Try-catch (universal)
  'err-003': ['error-classification'],         // Error classification (HTTP)
  'err-004': [],                               // Error logging (universal)

  // Webhook rules
  'wh-001': ['webhook-signature'],             // No Signature Validation
  'wh-002': ['replay-protection'],             // No Replay Protection
  'wh-003': ['webhook-signature'],             // Weak Signature Algorithm

  // Data integrity rules
  'di-001': ['idempotency-keys'],              // No Idempotency
  'di-002': [],                                // Transaction handling (universal)
  'di-003': ['dead-letter-queue'],             // No DLQ

  // Compliance rules - these check for sensitive data, always apply
  'comp-001': [],                              // Universal
  'comp-002': [],                              // Universal
  'comp-003': [],                              // Universal

  // MCP-specific rules
  'mcp-001': ['mcp-health-checks'],            // No /health endpoint
  'mcp-002': ['mcp-health-checks'],            // No /health/ready endpoint
  'mcp-003': ['mcp-health-checks'],            // No /health/detailed endpoint
  'mcp-004': ['mcp-error-codes'],              // Non-standard error codes
  'mcp-005': ['mcp-logging'],                  // No structured logging
  'mcp-006': ['mcp-logging'],                  // No correlation IDs

  // HTTP layer rules
  'http-001': ['rate-limit-inbound'],          // No inbound rate limiting
  'http-002': ['request-id-tracing'],          // No request ID
  'http-003': ['graceful-shutdown'],           // No graceful shutdown
  'http-004': ['error-classification']         // No error classification
};

/**
 * Universal rules that always apply regardless of profile
 */
const UNIVERSAL_RULES = new Set([
  // Security
  'comp-001', 'comp-002', 'comp-003',
  // Basic error handling
  'err-001', 'err-002', 'err-004',
  // Data integrity basics
  'di-002'
]);

export interface RuleFilterResult {
  ruleId: string;
  shouldApply: boolean;
  reason: string;
  categories: string[];
}

/**
 * Check if a specific rule should apply to a server profile
 */
export function shouldApplyRule(
  ruleId: string,
  profile: ServerProfile
): RuleFilterResult {
  // Universal rules always apply
  if (UNIVERSAL_RULES.has(ruleId)) {
    return {
      ruleId,
      shouldApply: true,
      reason: 'Universal rule - always applies',
      categories: []
    };
  }

  // Get categories for this rule
  const categories = RULE_CATEGORY_MAP[ruleId] || [];

  // If no categories mapped, it's potentially universal
  if (categories.length === 0) {
    return {
      ruleId,
      shouldApply: true,
      reason: 'No specific profile requirements',
      categories: []
    };
  }

  // Check each category's requirements
  for (const category of categories) {
    const applicability = RULE_APPLICABILITY.find(a => a.category === category);
    if (!applicability) continue;

    // Check if all required profile flags are met
    const requirementsMet = checkRequirements(applicability.requires, profile);
    if (!requirementsMet) {
      return {
        ruleId,
        shouldApply: false,
        reason: `Server profile does not match: ${applicability.description}`,
        categories
      };
    }
  }

  return {
    ruleId,
    shouldApply: true,
    reason: 'Profile requirements met',
    categories
  };
}

/**
 * Check if profile meets requirements
 */
function checkRequirements(
  requires: Partial<ServerProfile>,
  profile: ServerProfile
): boolean {
  for (const [key, value] of Object.entries(requires)) {
    if (value === true && profile[key as keyof ServerProfile] !== true) {
      return false;
    }
  }
  return true;
}

/**
 * Filter a list of rule IDs based on profile
 */
export function filterRules(
  ruleIds: string[],
  profile: ServerProfile
): { applied: string[]; skipped: RuleFilterResult[] } {
  const applied: string[] = [];
  const skipped: RuleFilterResult[] = [];

  for (const ruleId of ruleIds) {
    const result = shouldApplyRule(ruleId, profile);
    if (result.shouldApply) {
      applied.push(ruleId);
    } else {
      skipped.push(result);
    }
  }

  return { applied, skipped };
}

/**
 * Get a summary of which rule categories apply to a profile
 */
export function getApplicableCategories(profile: ServerProfile): string[] {
  const applicable: string[] = [];

  for (const applicability of RULE_APPLICABILITY) {
    if (checkRequirements(applicability.requires, profile)) {
      applicable.push(applicability.category);
    }
  }

  return applicable;
}

/**
 * Get a summary of which rule categories are skipped for a profile
 */
export function getSkippedCategories(profile: ServerProfile): { category: string; reason: string }[] {
  const skipped: { category: string; reason: string }[] = [];

  for (const applicability of RULE_APPLICABILITY) {
    if (!checkRequirements(applicability.requires, profile)) {
      skipped.push({
        category: applicability.category,
        reason: applicability.description
      });
    }
  }

  return skipped;
}

/**
 * Register a custom rule category mapping
 */
export function registerRuleCategory(ruleId: string, categories: string[]): void {
  RULE_CATEGORY_MAP[ruleId] = categories;
}

/**
 * Check if a rule category requires external API capability
 */
export function categoryRequiresExternalAPIs(category: string): boolean {
  const applicability = RULE_APPLICABILITY.find(a => a.category === category);
  return applicability?.requires.hasExternalAPIs === true;
}
