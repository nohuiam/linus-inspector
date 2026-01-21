/**
 * Linus Inspector Rules Index
 *
 * Exports all research-backed inspection rules:
 * - Rate Limiting (35-40% of failures)
 * - OAuth/Auth (10-20% of failures)
 * - Error Handling (25-30% of failures)
 * - Webhooks (12-20% of failures)
 * - Compliance (HIPAA, GDPR, SOC 2, PCI-DSS)
 * - Data Integrity (8-10% but highest cost)
 * - MCP Standards (health, error codes, logging)
 *
 * Supports profile-aware inspection to reduce false positives.
 */

export * from './rate-limit-rules.js';
export * from './oauth-rules.js';
export * from './error-rules.js';
export * from './webhook-rules.js';
export * from './compliance-rules.js';
export * from './data-integrity-rules.js';
export * from './meta-rules.js';
export * from './mcp-standards.js';

import { checkRateLimitRules, type RateLimitViolation, RATE_LIMIT_RULES } from './rate-limit-rules.js';
import { checkOAuthRules, type OAuthViolation } from './oauth-rules.js';
import { checkErrorRules, type ErrorViolation } from './error-rules.js';
import { checkWebhookRules, type WebhookViolation } from './webhook-rules.js';
import { checkComplianceRules, type ComplianceViolation } from './compliance-rules.js';
import { checkDataIntegrityRules, type DataIntegrityViolation } from './data-integrity-rules.js';
import { checkMCPStandardRules, type MCPViolation } from './mcp-standards.js';
import type { ServerProfile } from '../profiler/server-profile.js';

export type AnyViolation =
  | RateLimitViolation
  | OAuthViolation
  | ErrorViolation
  | WebhookViolation
  | ComplianceViolation
  | DataIntegrityViolation
  | MCPViolation;

export interface InspectionResult {
  category: string;
  violations: AnyViolation[];
  passed: boolean;
}

export interface FullInspectionResult {
  results: InspectionResult[];
  summary: {
    total_violations: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    auto_fixable: number;
  };
  verdict: 'PASSED' | 'BLOCKED' | 'WARNING';
}

/**
 * Run all inspection rules against code
 */
export function runAllInspections(
  code: string,
  options: {
    vendor?: string;
    regulation?: string;
  } = {}
): FullInspectionResult {
  const results: InspectionResult[] = [];

  // Rate Limiting
  const rateLimitViolations = checkRateLimitRules(code, options.vendor);
  results.push({
    category: 'rate_limiting',
    violations: rateLimitViolations,
    passed: rateLimitViolations.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length === 0
  });

  // OAuth
  const oauthViolations = checkOAuthRules(code, options.vendor);
  results.push({
    category: 'oauth',
    violations: oauthViolations,
    passed: oauthViolations.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length === 0
  });

  // Error Handling
  const errorViolations = checkErrorRules(code);
  results.push({
    category: 'error_handling',
    violations: errorViolations,
    passed: errorViolations.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length === 0
  });

  // Webhooks
  const webhookViolations = checkWebhookRules(code, options.vendor);
  results.push({
    category: 'webhooks',
    violations: webhookViolations,
    passed: webhookViolations.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length === 0
  });

  // Compliance
  const complianceViolations = checkComplianceRules(code, options.regulation);
  results.push({
    category: 'compliance',
    violations: complianceViolations,
    passed: complianceViolations.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length === 0
  });

  // Data Integrity
  const dataIntegrityViolations = checkDataIntegrityRules(code, options.vendor);
  results.push({
    category: 'data_integrity',
    violations: dataIntegrityViolations,
    passed: dataIntegrityViolations.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length === 0
  });

  // Calculate summary
  const allViolations = results.flatMap(r => r.violations);
  const summary = {
    total_violations: allViolations.length,
    critical: allViolations.filter(v => v.severity === 'CRITICAL').length,
    high: allViolations.filter(v => v.severity === 'HIGH').length,
    medium: allViolations.filter(v => v.severity === 'MEDIUM').length,
    low: allViolations.filter(v => v.severity === 'LOW').length,
    auto_fixable: allViolations.filter(v => v.auto_fixable).length
  };

  // Determine verdict
  let verdict: 'PASSED' | 'BLOCKED' | 'WARNING';
  if (summary.critical > 0 || summary.high > 0) {
    verdict = 'BLOCKED';
  } else if (summary.medium > 0) {
    verdict = 'WARNING';
  } else {
    verdict = 'PASSED';
  }

  return { results, summary, verdict };
}

/**
 * Get vendor-specific rule configuration
 */
export function getVendorRuleConfig(vendor: string): {
  rate_limits: import('./rate-limit-rules.js').RateLimitConfig | null;
  oauth: import('./oauth-rules.js').OAuthConfig | null;
  webhooks: import('./webhook-rules.js').WebhookConfig | null;
} {
  const { getVendorRateLimitConfig } = require('./rate-limit-rules.js');
  const { getVendorOAuthConfig } = require('./oauth-rules.js');
  const { getVendorWebhookConfig } = require('./webhook-rules.js');

  return {
    rate_limits: getVendorRateLimitConfig(vendor),
    oauth: getVendorOAuthConfig(vendor),
    webhooks: getVendorWebhookConfig(vendor)
  };
}

/**
 * List all supported vendors
 */
export const SUPPORTED_VENDORS = [
  'salesforce',
  'hubspot',
  'stripe',
  'snowflake',
  'zendesk',
  'slack',
  'quickbooks',
  'shopify',
  'servicenow',
  'microsoft365'
] as const;

export type SupportedVendor = typeof SUPPORTED_VENDORS[number];

/**
 * List all supported compliance regulations
 */
export const SUPPORTED_REGULATIONS = [
  'HIPAA',
  'GDPR',
  'SOC2',
  'PCI-DSS'
] as const;

export type SupportedRegulation = typeof SUPPORTED_REGULATIONS[number];

/**
 * Profile-aware inspection result with skipped rules
 */
export interface ProfileAwareInspectionResult extends FullInspectionResult {
  profile: ServerProfile;
  skipped_categories: { category: string; reason: string }[];
  applied_categories: string[];
}

/**
 * Run profile-aware inspections
 * Only applies rules that are relevant to the server's profile.
 */
export function runProfileAwareInspections(
  code: string,
  profile: ServerProfile,
  options: {
    vendor?: string;
    regulation?: string;
  } = {}
): ProfileAwareInspectionResult {
  const results: InspectionResult[] = [];
  const skippedCategories: { category: string; reason: string }[] = [];
  const appliedCategories: string[] = [];

  // Rate Limiting - only if server makes external API calls
  if (profile.hasExternalAPIs) {
    const rateLimitViolations = checkRateLimitRules(code, options.vendor);
    results.push({
      category: 'rate_limiting',
      violations: rateLimitViolations,
      passed: rateLimitViolations.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length === 0
    });
    appliedCategories.push('rate_limiting');
  } else {
    skippedCategories.push({
      category: 'rate_limiting',
      reason: 'Server does not make external API calls'
    });
  }

  // OAuth - only if server uses OAuth
  if (profile.hasOAuth) {
    const oauthViolations = checkOAuthRules(code, options.vendor);
    results.push({
      category: 'oauth',
      violations: oauthViolations,
      passed: oauthViolations.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length === 0
    });
    appliedCategories.push('oauth');
  } else {
    skippedCategories.push({
      category: 'oauth',
      reason: 'Server does not use OAuth'
    });
  }

  // Error Handling - always apply (universal)
  const errorViolations = checkErrorRules(code);
  results.push({
    category: 'error_handling',
    violations: errorViolations,
    passed: errorViolations.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length === 0
  });
  appliedCategories.push('error_handling');

  // Webhooks - only if server handles webhooks
  if (profile.hasWebhooks) {
    const webhookViolations = checkWebhookRules(code, options.vendor);
    results.push({
      category: 'webhooks',
      violations: webhookViolations,
      passed: webhookViolations.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length === 0
    });
    appliedCategories.push('webhooks');
  } else {
    skippedCategories.push({
      category: 'webhooks',
      reason: 'Server does not handle webhooks'
    });
  }

  // Compliance - always apply (security checks)
  const complianceViolations = checkComplianceRules(code, options.regulation);
  results.push({
    category: 'compliance',
    violations: complianceViolations,
    passed: complianceViolations.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length === 0
  });
  appliedCategories.push('compliance');

  // Data Integrity - apply if has external APIs or database writes
  if (profile.hasExternalAPIs || profile.hasDatabaseWrites) {
    const dataIntegrityViolations = checkDataIntegrityRules(code, options.vendor);
    results.push({
      category: 'data_integrity',
      violations: dataIntegrityViolations,
      passed: dataIntegrityViolations.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length === 0
    });
    appliedCategories.push('data_integrity');
  } else {
    skippedCategories.push({
      category: 'data_integrity',
      reason: 'Server does not have external APIs or database writes requiring idempotency'
    });
  }

  // MCP Standards - apply if is MCP server
  if (profile.isMCPServer) {
    const mcpViolations = checkMCPStandardRules(code);
    results.push({
      category: 'mcp_standards',
      violations: mcpViolations,
      passed: mcpViolations.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length === 0
    });
    appliedCategories.push('mcp_standards');
  } else {
    skippedCategories.push({
      category: 'mcp_standards',
      reason: 'Server is not an MCP server'
    });
  }

  // Calculate summary
  const allViolations = results.flatMap(r => r.violations);
  const summary = {
    total_violations: allViolations.length,
    critical: allViolations.filter(v => v.severity === 'CRITICAL').length,
    high: allViolations.filter(v => v.severity === 'HIGH').length,
    medium: allViolations.filter(v => v.severity === 'MEDIUM').length,
    low: allViolations.filter(v => v.severity === 'LOW').length,
    auto_fixable: allViolations.filter(v => v.auto_fixable).length
  };

  // Determine verdict
  let verdict: 'PASSED' | 'BLOCKED' | 'WARNING';
  if (summary.critical > 0 || summary.high > 0) {
    verdict = 'BLOCKED';
  } else if (summary.medium > 0) {
    verdict = 'WARNING';
  } else {
    verdict = 'PASSED';
  }

  return {
    results,
    summary,
    verdict,
    profile,
    skipped_categories: skippedCategories,
    applied_categories: appliedCategories
  };
}
