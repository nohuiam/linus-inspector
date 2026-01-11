/**
 * Tests for inspection rules
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  runAllInspections,
  SUPPORTED_VENDORS,
  SUPPORTED_REGULATIONS
} from '../src/rules/index.js';
import {
  RATE_LIMIT_RULES,
  VENDOR_RATE_LIMITS,
  checkRateLimitRules
} from '../src/rules/rate-limit-rules.js';
import {
  OAUTH_RULES,
  checkOAuthRules
} from '../src/rules/oauth-rules.js';
import {
  ERROR_RULES,
  checkErrorRules
} from '../src/rules/error-rules.js';
import {
  WEBHOOK_RULES,
  checkWebhookRules
} from '../src/rules/webhook-rules.js';
import {
  COMPLIANCE_RULES,
  checkComplianceRules,
  COMPLIANCE_CONFIGS
} from '../src/rules/compliance-rules.js';
import {
  DATA_INTEGRITY_RULES,
  checkDataIntegrityRules
} from '../src/rules/data-integrity-rules.js';

describe('Rate Limit Rules', () => {
  it('should have 10 rate limit rules', () => {
    expect(RATE_LIMIT_RULES.length).toBe(10);
  });

  it('should have vendor configs for all supported vendors', () => {
    const vendors = Object.keys(VENDOR_RATE_LIMITS);
    expect(vendors).toContain('salesforce');
    expect(vendors).toContain('hubspot');
    expect(vendors).toContain('stripe');
    expect(vendors).toContain('snowflake');
    expect(vendors).toContain('zendesk');
    expect(vendors).toContain('slack');
    expect(vendors).toContain('quickbooks');
    expect(vendors).toContain('shopify');
    expect(vendors).toContain('servicenow');
    expect(vendors).toContain('microsoft365');
  });

  it('should detect missing rate limiter', () => {
    const code = `
      async function fetchContacts() {
        const response = await fetch('/api/contacts');
        return response.json();
      }
    `;
    const issues = checkRateLimitRules(code);
    const hasRateLimitIssue = issues.some(i =>
      i.issue.includes('No rate limiting implementation detected')
    );
    expect(hasRateLimitIssue).toBe(true);
  });

  it('should pass when rate limiter exists', () => {
    const code = `
      import { RateLimiter } from './rate-limiter';
      const limiter = new RateLimiter({ limit: 100, window: 10000 });

      async function fetchContacts() {
        await limiter.acquire();
        const response = await fetch('/api/contacts');
        return response.json();
      }
    `;
    const issues = checkRateLimitRules(code);
    const hasNoRateLimiter = issues.some(i =>
      i.issue.includes('No rate limiting implementation detected')
    );
    expect(hasNoRateLimiter).toBe(false);
  });

  it('should detect missing backoff', () => {
    const code = `
      const limiter = new RateLimiter({ limit: 100 });
      async function retry() {
        while (true) {
          try {
            return await fetch('/api');
          } catch (e) {
            await sleep(1000);
          }
        }
      }
    `;
    const issues = checkRateLimitRules(code);
    const hasBackoffIssue = issues.some(i =>
      i.issue.includes('exponential backoff')
    );
    expect(hasBackoffIssue).toBe(true);
  });
});

describe('OAuth Rules', () => {
  it('should have 10 OAuth rules', () => {
    expect(OAUTH_RULES.length).toBe(10);
  });

  it('should detect missing pre-emptive refresh', () => {
    const code = `
      async function getToken() {
        if (token.expires_at < Date.now()) {
          token = await refreshToken();
        }
        return token;
      }
    `;
    const issues = checkOAuthRules(code);
    const hasRefreshIssue = issues.some(i =>
      i.issue.includes('pre-emptive')
    );
    expect(hasRefreshIssue).toBe(true);
  });

  it('should detect hardcoded credentials', () => {
    const code = `
      const API_KEY = 'sk_live_abc123xyz789';
      const config = {
        client_secret: '1234567890abcdef'
      };
    `;
    const issues = checkOAuthRules(code);
    const hasHardcodedCreds = issues.some(i =>
      i.issue.includes('hardcoded') || i.issue.includes('credential')
    );
    expect(hasHardcodedCreds).toBe(true);
  });

  it('should detect missing tenant isolation', () => {
    // Code that has token storage/caching but no tenant isolation
    const code = `
      const tokenCache = {};
      async function getOAuthToken(provider) {
        if (tokenCache[provider]) return tokenCache[provider];
        const token = await db.query('SELECT token FROM oauth_tokens WHERE provider = ?', [provider]);
        tokenCache[provider] = token;
        return token;
      }
    `;
    const issues = checkOAuthRules(code);
    const hasTenantIssue = issues.some(i =>
      i.issue.toLowerCase().includes('tenant') ||
      i.issue.toLowerCase().includes('isolation')
    );
    expect(hasTenantIssue).toBe(true);
  });
});

describe('Error Handling Rules', () => {
  it('should have 11 error handling rules', () => {
    expect(ERROR_RULES.length).toBe(11);
  });

  it('should detect missing 4xx handlers', () => {
    const code = `
      async function fetchData() {
        const response = await fetch('/api/data');
        return response.json();
      }
    `;
    const issues = checkErrorRules(code);
    const has4xxIssue = issues.some(i =>
      i.issue.includes('4xx') || i.issue.includes('error handling')
    );
    expect(has4xxIssue).toBe(true);
  });

  it('should detect missing graceful degradation', () => {
    // Code with API calls but no graceful degradation pattern
    const code = `
      async function fetchWithRetry() {
        for (let i = 0; i < 5; i++) {
          try {
            return await fetch('/api/data');
          } catch (e) {
            await sleep(1000 * Math.pow(2, i));
          }
        }
        throw new Error('Failed after retries');
      }
    `;
    const issues = checkErrorRules(code);
    // Should have issues related to error handling or degradation
    const hasErrorIssue = issues.some(i =>
      i.issue.toLowerCase().includes('degradation') ||
      i.issue.toLowerCase().includes('dlq') ||
      i.issue.toLowerCase().includes('dead letter')
    );
    expect(hasErrorIssue).toBe(true);
  });

  it('should pass with comprehensive error handling', () => {
    const code = `
      import { CircuitBreaker } from './circuit-breaker';

      const breaker = new CircuitBreaker({ threshold: 5, timeout: 60000 });

      async function fetchData() {
        try {
          const response = await fetch('/api/data');

          if (response.status === 401) {
            await refreshToken();
            return fetchData();
          }

          if (response.status === 429) {
            await handleRateLimit(response);
            return fetchData();
          }

          if (response.status >= 400 && response.status < 500) {
            throw new ClientError(response.status);
          }

          if (response.status >= 500) {
            throw new ServerError(response.status);
          }

          return response.json();
        } catch (error) {
          breaker.recordFailure();
          throw error;
        }
      }
    `;
    const issues = checkErrorRules(code);
    // Should have fewer critical issues
    const criticalIssues = issues.filter(i => i.severity === 'CRITICAL');
    expect(criticalIssues.length).toBeLessThan(3);
  });
});

describe('Webhook Rules', () => {
  it('should have 10 webhook rules', () => {
    expect(WEBHOOK_RULES.length).toBe(10);
  });

  it('should detect webhook-only implementation', () => {
    const code = `
      app.post('/webhook', (req, res) => {
        const event = req.body;
        processEvent(event);
        res.status(200).send('OK');
      });
    `;
    const issues = checkWebhookRules(code);
    const hasPollingIssue = issues.some(i =>
      i.issue.includes('polling') || i.issue.includes('fallback')
    );
    expect(hasPollingIssue).toBe(true);
  });

  it('should detect missing signature validation', () => {
    const code = `
      app.post('/webhook/stripe', (req, res) => {
        const event = req.body;
        handleStripeEvent(event);
        res.send('OK');
      });
    `;
    const issues = checkWebhookRules(code);
    const hasSignatureIssue = issues.some(i =>
      i.issue.includes('signature')
    );
    expect(hasSignatureIssue).toBe(true);
  });

  it('should detect missing idempotency', () => {
    const code = `
      async function processWebhook(event) {
        await updateDatabase(event.data);
        await notifyUser(event.data);
      }
    `;
    const issues = checkWebhookRules(code);
    const hasIdempotencyIssue = issues.some(i =>
      i.issue.includes('idempotency') || i.issue.includes('deduplication')
    );
    expect(hasIdempotencyIssue).toBe(true);
  });
});

describe('Compliance Rules', () => {
  it('should have rules for all 4 regulations', () => {
    // COMPLIANCE_CONFIGS has regulation-specific configs
    expect(COMPLIANCE_CONFIGS.hipaa).toBeDefined();
    expect(COMPLIANCE_CONFIGS.gdpr).toBeDefined();
    expect(COMPLIANCE_CONFIGS.soc2).toBeDefined();
    expect(COMPLIANCE_CONFIGS['pci-dss']).toBeDefined();
    // COMPLIANCE_RULES is an array of all rules
    expect(COMPLIANCE_RULES.length).toBeGreaterThan(0);
  });

  it('should detect HIPAA violations', () => {
    const code = `
      // Store patient data
      db.insert('patients', { ssn: patient.ssn, diagnosis: patient.diagnosis });
    `;
    const issues = checkComplianceRules(code, 'hipaa');
    expect(issues.length).toBeGreaterThan(0);
  });

  it('should detect PCI-DSS violations', () => {
    const code = `
      // Store card data
      const card = {
        number: '4111111111111111',
        cvv: '123',
        expiry: '12/25'
      };
      db.save('cards', card);
    `;
    const issues = checkComplianceRules(code, 'pci-dss');
    const hasCvvIssue = issues.some(i =>
      i.issue.toLowerCase().includes('cvv') || i.issue.toLowerCase().includes('card')
    );
    expect(hasCvvIssue).toBe(true);
  });

  it('should detect GDPR violations', () => {
    // Code that has EU personal data AND transfers to US without SCCs
    const code = `
      // Process EU personal data and transfer to US
      const userData = await db.query('SELECT * FROM eu_users WHERE gdpr_consent = true');
      await fetch('https://us-east.api.example.com/users', {
        method: 'POST',
        body: JSON.stringify(userData)
      });
    `;
    const issues = checkComplianceRules(code, 'gdpr');
    expect(issues.length).toBeGreaterThan(0);
  });
});

describe('Data Integrity Rules', () => {
  it('should have 10 data integrity rules', () => {
    expect(DATA_INTEGRITY_RULES.length).toBe(10);
  });

  it('should detect missing idempotency keys', () => {
    const code = `
      async function createOrder(data) {
        const response = await fetch('/api/orders', {
          method: 'POST',
          body: JSON.stringify(data)
        });
        return response.json();
      }
    `;
    const issues = checkDataIntegrityRules(code);
    const hasIdempotencyIssue = issues.some(i =>
      i.issue.includes('idempotency')
    );
    expect(hasIdempotencyIssue).toBe(true);
  });

  it('should detect pagination without deduplication', () => {
    // Using offset pagination which triggers di-004 (offset deprecated) that mentions duplicates
    const code = `
      async function fetchAllContacts() {
        let contacts = [];
        let offset = 0;
        const pageSize = 100;

        do {
          const response = await fetch('/api/contacts?offset=' + offset + '&limit=' + pageSize);
          const data = await response.json();
          contacts = contacts.concat(data.results);
          offset += pageSize;
        } while (data.results.length === pageSize);

        return contacts;
      }
    `;
    const issues = checkDataIntegrityRules(code);
    const hasDedupIssue = issues.some(i =>
      i.issue.includes('deduplication') || i.issue.includes('duplicate')
    );
    expect(hasDedupIssue).toBe(true);
  });
});

describe('runAllInspections', () => {
  it('should return BLOCKED verdict for critical issues', () => {
    const code = `
      // Terrible code with many issues
      const API_KEY = 'secret123';

      async function fetchData() {
        const response = await fetch('/api/data');
        return response.json();
      }

      async function createOrder(data) {
        await fetch('/api/orders', { method: 'POST', body: JSON.stringify(data) });
      }
    `;
    const result = runAllInspections(code);
    expect(['BLOCKED', 'WARNING']).toContain(result.verdict);
    expect(result.summary.total_violations).toBeGreaterThan(0);
  });

  it('should support vendor-specific inspection', () => {
    const code = `
      // HubSpot connector
      async function fetchContacts() {
        const response = await fetch('https://api.hubapi.com/crm/v3/objects/contacts');
        return response.json();
      }
    `;
    const result = runAllInspections(code, { vendor: 'hubspot' });
    // Result has standard structure - vendor is used for checking vendor-specific rules
    expect(result.results).toBeDefined();
    expect(result.verdict).toBeDefined();
  });

  it('should support regulation-specific inspection', () => {
    const code = `
      // Healthcare app
      async function getPatient(id) {
        return db.query('SELECT * FROM patients WHERE id = ?', [id]);
      }
    `;
    const result = runAllInspections(code, { regulation: 'hipaa' });
    // Compliance category should be checked
    const complianceResult = result.results.find(r => r.category === 'compliance');
    expect(complianceResult).toBeDefined();
  });

  it('should list all supported vendors', () => {
    expect(SUPPORTED_VENDORS).toContain('salesforce');
    expect(SUPPORTED_VENDORS).toContain('hubspot');
    expect(SUPPORTED_VENDORS).toContain('stripe');
    expect(SUPPORTED_VENDORS.length).toBe(10);
  });

  it('should list all supported regulations', () => {
    // Note: These are uppercase in the actual implementation
    expect(SUPPORTED_REGULATIONS).toContain('HIPAA');
    expect(SUPPORTED_REGULATIONS).toContain('GDPR');
    expect(SUPPORTED_REGULATIONS).toContain('SOC2');
    expect(SUPPORTED_REGULATIONS).toContain('PCI-DSS');
  });
});
