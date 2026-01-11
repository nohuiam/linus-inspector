/**
 * Tests for meta-rules (physician heal thyself)
 */

import { describe, it, expect } from 'vitest';
import {
  checkMetaRules,
  getMetaRulesSummary,
  type MetaInspectionContext
} from '../src/rules/meta-rules.js';

describe('Meta-Rules', () => {
  const inspectorContext: MetaInspectionContext = {
    is_inspector: true,
    server_type: 'inspector',
    inspection_categories: ['rate_limiting', 'error_handling']
  };

  describe('meta-001: Rate-Limit Inspector Without Rate Limiting', () => {
    it('should detect rate-limit inspector without rate limiting', () => {
      // Code that checks for throttling in others but doesn't implement it itself
      // Avoid using "rateLimit" in variable names to not trigger false positive
      const codeWithoutRateLimit = `
        // This inspector checks throttling in other code
        const checkThrottle = (code) => {
          return code.includes('throttle');
        };

        app.post('/api/inspect', async (req, res) => {
          const result = checkThrottle(req.body.code);
          res.json(result);
        });
      `;

      const violations = checkMetaRules(codeWithoutRateLimit, inspectorContext);
      const meta001 = violations.find(v => v.rule_id === 'meta-001');

      expect(meta001).toBeDefined();
      expect(meta001?.severity).toBe('CRITICAL');
      expect(meta001?.irony_level).toBe('maximum');
    });

    it('should pass when rate limiting is present', () => {
      const codeWithRateLimit = `
        import { createRateLimiter } from './middleware';

        app.use(createRateLimiter({ windowMs: 60000, max: 100 }));

        app.post('/api/inspect', async (req, res) => {
          const result = checkThrottle(req.body.code);
          res.json(result);
        });
      `;

      const violations = checkMetaRules(codeWithRateLimit, inspectorContext);
      const meta001 = violations.find(v => v.rule_id === 'meta-001');

      expect(meta001).toBeUndefined();
    });
  });

  describe('meta-002: Error Inspector With Poor Error Handling', () => {
    it('should detect empty catch blocks', () => {
      const codeWithEmptyCatch = `
        // This checks for error handling
        const errorRules = ['catch', 'error'];

        try {
          doSomething();
        } catch (e) {
        }
      `;

      const violations = checkMetaRules(codeWithEmptyCatch, inspectorContext);
      const meta002 = violations.find(v => v.rule_id === 'meta-002' && v.severity === 'HIGH');

      expect(meta002).toBeDefined();
      expect(meta002?.issue).toContain('empty catch');
    });

    it('should detect catch-only-log patterns', () => {
      const codeWithCatchLog = `
        // Error handling inspector
        const checkErrorHandling = () => {};

        try {
          doSomething();
        } catch (e) {
          console.log(e);
        }
      `;

      const violations = checkMetaRules(codeWithCatchLog, inspectorContext);
      const meta002 = violations.find(v => v.rule_id === 'meta-002' && v.severity === 'MEDIUM');

      expect(meta002).toBeDefined();
      expect(meta002?.issue).toContain('only logging');
    });
  });

  describe('meta-004: Regex Rules Without Multiline Flag', () => {
    it('should detect regex patterns without multiline flag', () => {
      const codeWithBadRegex = `
        const emptyCatch = /catch\\s*\\([^)]*\\)\\s*{\\s*}/;
        const functionPattern = /function\\s+\\w+/;
      `;

      const violations = checkMetaRules(codeWithBadRegex, inspectorContext);
      const meta004 = violations.find(v => v.rule_id === 'meta-004');

      expect(meta004).toBeDefined();
      expect(meta004?.severity).toBe('MEDIUM');
    });

    it('should pass when multiline flag is present', () => {
      const codeWithGoodRegex = `
        const emptyCatch = /catch\\s*\\([^)]*\\)\\s*{\\s*}/m;
      `;

      const violations = checkMetaRules(codeWithGoodRegex, inspectorContext);
      const meta004 = violations.find(v => v.rule_id === 'meta-004');

      expect(meta004).toBeUndefined();
    });
  });

  describe('meta-005: HTTP Endpoints Without Timeout', () => {
    it('should detect async handlers without timeout', () => {
      const codeWithoutTimeout = `
        app.post('/api/inspect', async (req, res) => {
          const result = await longRunningOperation();
          res.json(result);
        });
      `;

      const violations = checkMetaRules(codeWithoutTimeout, inspectorContext);
      const meta005 = violations.find(v => v.rule_id === 'meta-005');

      expect(meta005).toBeDefined();
      expect(meta005?.severity).toBe('HIGH');
    });

    it('should pass when timeout wrapper is present', () => {
      const codeWithTimeout = `
        app.post('/api/inspect', withTimeout(async (req, res) => {
          const result = await longRunningOperation();
          res.json(result);
        }, 30000));
      `;

      const violations = checkMetaRules(codeWithTimeout, inspectorContext);
      const meta005 = violations.find(v => v.rule_id === 'meta-005');

      expect(meta005).toBeUndefined();
    });
  });

  describe('meta-008: Security Inspector With Hardcoded Secrets', () => {
    it('should detect hardcoded API keys', () => {
      const context: MetaInspectionContext = {
        is_inspector: true,
        server_type: 'inspector',
        inspection_categories: ['security']
      };

      const codeWithHardcodedKey = `
        // Security inspector
        const checkCredentials = (code) => code.includes('api_key');
        const api_key = "testfakekeynotreal1234567890abcdef";
      `;

      const violations = checkMetaRules(codeWithHardcodedKey, context);
      const meta008 = violations.find(v => v.rule_id === 'meta-008');

      expect(meta008).toBeDefined();
      expect(meta008?.severity).toBe('CRITICAL');
      expect(meta008?.irony_level).toBe('maximum');
    });

    it('should pass when no hardcoded secrets', () => {
      const context: MetaInspectionContext = {
        is_inspector: true,
        server_type: 'inspector',
        inspection_categories: ['security']
      };

      const codeWithEnvVars = `
        // Security inspector
        const checkCredentials = (code) => code.includes('api_key');
        const apiKey = process.env.API_KEY;
      `;

      const violations = checkMetaRules(codeWithEnvVars, context);
      const meta008 = violations.find(v => v.rule_id === 'meta-008');

      expect(meta008).toBeUndefined();
    });
  });

  describe('Meta-Rules Summary', () => {
    it('should return summary of all meta-rules', () => {
      const summary = getMetaRulesSummary();

      expect(summary.total).toBeGreaterThan(0);
      expect(summary.by_severity).toBeDefined();
      expect(summary.by_irony).toBeDefined();
      expect(summary.by_severity['CRITICAL']).toBeGreaterThan(0);
      expect(summary.by_irony['maximum']).toBeGreaterThan(0);
    });
  });

  describe('Context Filtering', () => {
    it('should skip rules that do not apply to server type', () => {
      const otherContext: MetaInspectionContext = {
        is_inspector: false,
        server_type: 'other',
        inspection_categories: []
      };

      const code = `
        app.post('/api/data', async (req, res) => {
          res.json({ data: 'test' });
        });
      `;

      const violations = checkMetaRules(code, otherContext);

      // Most inspector-specific rules should not apply
      expect(violations.filter(v => v.rule_id === 'meta-001').length).toBe(0);
    });
  });
});
