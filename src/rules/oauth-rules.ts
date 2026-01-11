/**
 * OAuth/Auth Rules - Research-backed from Perplexity documents
 *
 * Auth failures account for 10-20% of API issues
 * Mean time to detect: 2 hours
 * Mean time to resolve: 1 hour
 * Revenue impact: $5K-$20K per incident
 *
 * Key issues:
 * - Token refresh race conditions
 * - Token revocation detection
 * - Multi-tenant isolation
 * - Scope validation
 */

export interface OAuthConfig {
  auth_type: 'oauth2' | 'api_key' | 'jwt' | 'api_token' | 'private_app' | 'smart_on_fhir' | 'x509';
  token_expiry_minutes?: number;
  refresh_buffer_minutes: number; // Pre-emptive refresh before expiry
  refresh_token_expiry_days?: number;
  reauth_days?: number; // Some platforms require re-authentication
  scopes_required?: string[];
}

export const VENDOR_OAUTH_CONFIGS: Record<string, OAuthConfig> = {
  salesforce: {
    auth_type: 'oauth2',
    token_expiry_minutes: 120, // 2 hours
    refresh_buffer_minutes: 5,
    refresh_token_expiry_days: 90
  },
  hubspot: {
    auth_type: 'private_app',
    token_expiry_minutes: 360, // 6 hours
    refresh_buffer_minutes: 5,
    refresh_token_expiry_days: 180 // 6 months
  },
  stripe: {
    auth_type: 'api_key',
    refresh_buffer_minutes: 0 // API keys don't expire
  },
  snowflake: {
    auth_type: 'jwt',
    token_expiry_minutes: 60, // 1 hour!
    refresh_buffer_minutes: 10 // Must refresh before 1 hour
  },
  zendesk: {
    auth_type: 'api_token',
    refresh_buffer_minutes: 0
  },
  slack: {
    auth_type: 'oauth2',
    refresh_buffer_minutes: 5
  },
  quickbooks: {
    auth_type: 'oauth2',
    token_expiry_minutes: 60,
    refresh_buffer_minutes: 5,
    reauth_days: 100 // Must re-authenticate after 100 days!
  },
  shopify: {
    auth_type: 'oauth2',
    refresh_buffer_minutes: 5
  },
  servicenow: {
    auth_type: 'oauth2',
    refresh_buffer_minutes: 5
  },
  microsoft365: {
    auth_type: 'oauth2',
    token_expiry_minutes: 60,
    refresh_buffer_minutes: 5
  }
};

export interface OAuthRule {
  id: string;
  name: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  check: (code: string, vendor?: string) => OAuthViolation[];
}

export interface OAuthViolation {
  rule_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  location?: string;
  issue: string;
  remedy: string;
  auto_fixable: boolean;
}

export const OAUTH_RULES: OAuthRule[] = [
  {
    id: 'oauth-001',
    name: 'No Pre-emptive Token Refresh',
    description: 'Must refresh tokens BEFORE they expire',
    severity: 'CRITICAL',
    check: (code: string, vendor?: string): OAuthViolation[] => {
      const violations: OAuthViolation[] = [];

      const hasTokenRefresh = /refresh[_-]?token|token[_-]?refresh/i.test(code);
      const hasPreemptiveRefresh = /buffer|before.*expir|expir.*before|pre.*refresh|early.*refresh/i.test(code);

      if (hasTokenRefresh && !hasPreemptiveRefresh) {
        const config = vendor ? VENDOR_OAUTH_CONFIGS[vendor] : null;
        violations.push({
          rule_id: 'oauth-001',
          severity: 'CRITICAL',
          issue: 'Token refresh detected but no pre-emptive refresh before expiry',
          remedy: config
            ? `Refresh token ${config.refresh_buffer_minutes} minutes BEFORE expiry for ${vendor}`
            : 'Refresh token 5 minutes BEFORE expiry to prevent race conditions',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'oauth-002',
    name: 'Token Refresh Race Condition',
    description: 'Must use async lock to prevent concurrent refresh calls',
    severity: 'CRITICAL',
    check: (code: string): OAuthViolation[] => {
      const violations: OAuthViolation[] = [];

      const hasTokenRefresh = /refresh[_-]?token|token[_-]?refresh/i.test(code);
      const hasAsyncLock = /lock|mutex|semaphore|atomic|synchronized/i.test(code);

      if (hasTokenRefresh && !hasAsyncLock) {
        violations.push({
          rule_id: 'oauth-002',
          severity: 'CRITICAL',
          issue: 'Token refresh without async lock - risk of race condition',
          remedy: 'Implement async lock: only first caller refreshes, others wait for result',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'oauth-003',
    name: 'No Token Revocation Detection',
    description: 'Must detect and handle token revocation (password change, etc.)',
    severity: 'HIGH',
    check: (code: string): OAuthViolation[] => {
      const violations: OAuthViolation[] = [];

      const hasOAuth = /oauth|token|access[_-]?token/i.test(code);
      const hasRevocationHandling = /invalid[_-]?grant|revok|password.*change|re-?auth/i.test(code);

      if (hasOAuth && !hasRevocationHandling) {
        violations.push({
          rule_id: 'oauth-003',
          severity: 'HIGH',
          issue: 'No token revocation detection (password change invalidates all tokens)',
          remedy: 'Handle invalid_grant errors: pause sync, alert user to re-authenticate',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'oauth-004',
    name: 'Multi-Tenant Token Isolation',
    description: 'CRITICAL: tenant_id must be in ALL token queries and cache keys',
    severity: 'CRITICAL',
    check: (code: string): OAuthViolation[] => {
      const violations: OAuthViolation[] = [];

      const hasTokenStorage = /token.*storage|store.*token|cache.*token|token.*cache/i.test(code);
      const hasTenantIsolation = /tenant[_-]?id|organization[_-]?id|org[_-]?id/i.test(code);
      const hasMultiTenant = /multi[_-]?tenant|tenants?/i.test(code);

      // If multi-tenant but no tenant isolation in token handling
      if ((hasTokenStorage || hasMultiTenant) && !hasTenantIsolation) {
        violations.push({
          rule_id: 'oauth-004',
          severity: 'CRITICAL',
          issue: 'Multi-tenant token handling without tenant_id isolation - SECURITY RISK',
          remedy: 'Add tenant_id to ALL queries (WHERE tenant_id = ?) and cache keys (oauth_token:{tenant_id}:{provider})',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'oauth-005',
    name: 'Snowflake JWT Expiry',
    description: 'Snowflake JWT expires in 1 hour - must refresh every 50 minutes',
    severity: 'HIGH',
    check: (code: string, vendor?: string): OAuthViolation[] => {
      const violations: OAuthViolation[] = [];

      if (vendor !== 'snowflake') return violations;

      const hasJwtRefresh = /jwt.*refresh|refresh.*jwt|50.*min|token.*refresh/i.test(code);

      if (!hasJwtRefresh) {
        violations.push({
          rule_id: 'oauth-005',
          severity: 'HIGH',
          issue: 'Snowflake JWT expires in 1 hour - no refresh detected',
          remedy: 'Implement JWT refresh every 50 minutes (10 min buffer before 1-hour expiry)',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'oauth-006',
    name: 'QuickBooks 100-Day Re-authentication',
    description: 'QuickBooks requires full re-authentication after 100 days',
    severity: 'HIGH',
    check: (code: string, vendor?: string): OAuthViolation[] => {
      const violations: OAuthViolation[] = [];

      if (vendor !== 'quickbooks') return violations;

      const hasReauthFlow = /100.*day|re-?auth|reconnect|re-?connect/i.test(code);

      if (!hasReauthFlow) {
        violations.push({
          rule_id: 'oauth-006',
          severity: 'HIGH',
          issue: 'QuickBooks requires re-authentication after 100 days - not handled',
          remedy: 'Implement 100-day reconnection flow with user notification',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'oauth-007',
    name: 'No Scope Validation',
    description: 'Must validate OAuth scopes before API calls',
    severity: 'MEDIUM',
    check: (code: string): OAuthViolation[] => {
      const violations: OAuthViolation[] = [];

      const hasOAuth = /oauth|scope|permission/i.test(code);
      const hasScopeCheck = /scope.*check|check.*scope|has.*scope|scope.*valid/i.test(code);

      if (hasOAuth && !hasScopeCheck) {
        violations.push({
          rule_id: 'oauth-007',
          severity: 'MEDIUM',
          issue: 'OAuth detected but no scope validation before API calls',
          remedy: 'Validate required scopes before making API calls to prevent partial failures',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'oauth-008',
    name: 'Hardcoded Credentials',
    description: 'Credentials must never be hardcoded in source',
    severity: 'CRITICAL',
    check: (code: string): OAuthViolation[] => {
      const violations: OAuthViolation[] = [];

      // Look for hardcoded API keys, secrets, tokens
      const patterns = [
        /api[_-]?key\s*[=:]\s*["'][a-zA-Z0-9]{20,}/i,
        /client[_-]?secret\s*[=:]\s*["'][a-zA-Z0-9]{20,}/i,
        /access[_-]?token\s*[=:]\s*["'][a-zA-Z0-9]{20,}/i,
        /bearer\s+[a-zA-Z0-9]{20,}/i,
        /sk_live_[a-zA-Z0-9]+/, // Stripe live key
        /sk_test_[a-zA-Z0-9]+/, // Stripe test key
      ];

      for (const pattern of patterns) {
        const match = code.match(pattern);
        if (match) {
          violations.push({
            rule_id: 'oauth-008',
            severity: 'CRITICAL',
            location: match[0].substring(0, 30) + '...',
            issue: 'Hardcoded credential detected in source code',
            remedy: 'Move credential to environment variable (e.g., process.env.API_KEY)',
            auto_fixable: true
          });
        }
      }

      return violations;
    }
  },
  {
    id: 'oauth-009',
    name: 'Slack Non-Marketplace Limits',
    description: 'Slack non-Marketplace apps limited to 1 req/min',
    severity: 'HIGH',
    check: (code: string, vendor?: string): OAuthViolation[] => {
      const violations: OAuthViolation[] = [];

      if (vendor !== 'slack') return violations;

      const hasMarketplaceCheck = /marketplace|app.*directory|published/i.test(code);

      if (!hasMarketplaceCheck) {
        violations.push({
          rule_id: 'oauth-009',
          severity: 'HIGH',
          issue: 'Slack non-Marketplace apps are limited to 1 req/min - not checked',
          remedy: 'Verify Marketplace approval status or implement 1 req/min fallback',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'oauth-010',
    name: 'No 401 Handler',
    description: 'Must handle 401 Unauthorized responses',
    severity: 'CRITICAL',
    check: (code: string): OAuthViolation[] => {
      const violations: OAuthViolation[] = [];

      const hasApiCalls = /fetch|axios|http|request|api/i.test(code);
      const has401Handler = /401|unauthorized|auth.*fail|token.*expir/i.test(code);

      if (hasApiCalls && !has401Handler) {
        violations.push({
          rule_id: 'oauth-010',
          severity: 'CRITICAL',
          issue: 'No handler for 401 Unauthorized responses',
          remedy: 'Add 401 handler: attempt token refresh, then retry request',
          auto_fixable: true
        });
      }

      return violations;
    }
  }
];

export function checkOAuthRules(code: string, vendor?: string): OAuthViolation[] {
  const violations: OAuthViolation[] = [];

  for (const rule of OAUTH_RULES) {
    violations.push(...rule.check(code, vendor));
  }

  return violations;
}

export function getVendorOAuthConfig(vendor: string): OAuthConfig | null {
  return VENDOR_OAUTH_CONFIGS[vendor.toLowerCase()] || null;
}
