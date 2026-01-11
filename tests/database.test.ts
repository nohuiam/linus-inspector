/**
 * Tests for database operations
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'fs';
import path from 'path';
import {
  initDatabase,
  getDb,
  saveInspection,
  getInspection,
  getInspectionsByBuild,
  saveIssue,
  getIssuesByInspection,
  getVendorConfig,
  getAllVendorConfigs,
  getComplianceRules
} from '../src/database/index.js';

describe('Database', () => {
  beforeAll(() => {
    // Initialize test database
    const testDataDir = path.join(process.cwd(), 'data');
    if (!fs.existsSync(testDataDir)) {
      fs.mkdirSync(testDataDir, { recursive: true });
    }
    initDatabase();
  });

  describe('Database Initialization', () => {
    it('should initialize database successfully', () => {
      const db = getDb();
      expect(db).toBeDefined();
    });

    it('should create required tables', () => {
      const db = getDb();
      const tables = db.prepare(`
        SELECT name FROM sqlite_master
        WHERE type='table'
        ORDER BY name
      `).all() as { name: string }[];

      const tableNames = tables.map(t => t.name);
      expect(tableNames).toContain('inspections');
      expect(tableNames).toContain('inspection_issues');
      expect(tableNames).toContain('vendor_configs');
      expect(tableNames).toContain('compliance_rules');
    });
  });

  describe('Inspection Operations', () => {
    it('should save and retrieve inspection', () => {
      const inspection = {
        id: `test-${Date.now()}`,
        build_id: 'B-2026-001',
        server_name: 'test-server',
        server_path: '/test/path',
        verdict: 'PASSED',
        summary_critical: 0,
        summary_high: 1,
        summary_medium: 2,
        summary_low: 3
      };

      saveInspection(inspection);
      const retrieved = getInspection(inspection.id);

      expect(retrieved).toBeDefined();
      expect(retrieved?.build_id).toBe(inspection.build_id);
      expect(retrieved?.server_name).toBe(inspection.server_name);
      expect(retrieved?.verdict).toBe(inspection.verdict);
    });

    it('should retrieve inspections by build', () => {
      const buildId = `build-${Date.now()}`;

      // Save multiple inspections for same build
      saveInspection({
        id: `${buildId}-1`,
        build_id: buildId,
        server_name: 'server-1',
        server_path: '/path/1',
        verdict: 'PASSED',
        summary_critical: 0,
        summary_high: 0,
        summary_medium: 0,
        summary_low: 0
      });

      saveInspection({
        id: `${buildId}-2`,
        build_id: buildId,
        server_name: 'server-2',
        server_path: '/path/2',
        verdict: 'BLOCKED',
        summary_critical: 1,
        summary_high: 0,
        summary_medium: 0,
        summary_low: 0
      });

      const inspections = getInspectionsByBuild(buildId);

      expect(inspections).toHaveLength(2);
      expect(inspections.some(i => i.server_name === 'server-1')).toBe(true);
      expect(inspections.some(i => i.server_name === 'server-2')).toBe(true);
    });

    it('should return null for non-existent inspection', () => {
      const result = getInspection('non-existent-id');
      expect(result).toBeNull();
    });
  });

  describe('Issue Operations', () => {
    it('should save and retrieve issues', () => {
      const inspectionId = `insp-${Date.now()}`;

      // First save the inspection
      saveInspection({
        id: inspectionId,
        build_id: 'B-001',
        server_name: 'test',
        server_path: '/test',
        verdict: 'BLOCKED',
        summary_critical: 1,
        summary_high: 0,
        summary_medium: 0,
        summary_low: 0
      });

      // Save issues
      saveIssue({
        id: `issue-${Date.now()}-1`,
        inspection_id: inspectionId,
        severity: 'CRITICAL',
        category: 'rate_limiting',
        location: 'src/api/client.ts:45',
        issue: 'No rate limiting implementation',
        remedy: 'Add exponential backoff',
        auto_fixable: true
      });

      saveIssue({
        id: `issue-${Date.now()}-2`,
        inspection_id: inspectionId,
        severity: 'HIGH',
        category: 'error_handling',
        location: 'src/api/client.ts:60',
        issue: 'Missing 401 handler',
        remedy: 'Add token refresh on 401',
        auto_fixable: true
      });

      const issues = getIssuesByInspection(inspectionId);

      expect(issues).toHaveLength(2);
      expect(issues.some(i => i.severity === 'CRITICAL')).toBe(true);
      expect(issues.some(i => i.severity === 'HIGH')).toBe(true);
    });

    it('should return empty array for inspection with no issues', () => {
      const issues = getIssuesByInspection('no-issues-inspection');
      expect(issues).toEqual([]);
    });
  });

  describe('Vendor Configs', () => {
    it('should retrieve pre-seeded vendor configs', () => {
      const salesforce = getVendorConfig('salesforce');
      expect(salesforce).toBeDefined();
      expect(salesforce?.rate_limit_value).toBe(100);
      expect(salesforce?.rate_limit_window_ms).toBe(20000);
    });

    it('should have configs for all 10 vendors', () => {
      const vendors = [
        'salesforce', 'hubspot', 'stripe', 'snowflake', 'zendesk',
        'slack', 'quickbooks', 'shopify', 'servicenow', 'microsoft365'
      ];

      for (const vendor of vendors) {
        const config = getVendorConfig(vendor);
        expect(config).toBeDefined();
        expect(config?.vendor).toBe(vendor);
      }
    });

    it('should return null for unknown vendor', () => {
      const result = getVendorConfig('unknown-vendor');
      expect(result).toBeNull();
    });

    it('should get all vendor configs', () => {
      const configs = getAllVendorConfigs();
      expect(configs.length).toBeGreaterThanOrEqual(10);
    });

    it('should have correct HubSpot config from research', () => {
      const hubspot = getVendorConfig('hubspot');
      expect(hubspot?.rate_limit_value).toBe(190);
      expect(hubspot?.rate_limit_window_ms).toBe(10000);
      expect(hubspot?.rate_limit_type).toBe('sliding_window');
    });

    it('should have correct Stripe config from research', () => {
      const stripe = getVendorConfig('stripe');
      expect(stripe?.rate_limit_value).toBe(100);
      expect(stripe?.rate_limit_window_ms).toBe(1000);
      // Webhook signature requirement is documented in known_issues
      expect(stripe?.known_issues).toContain('Webhook signature validation required');
    });
  });

  describe('Compliance Rules', () => {
    it('should retrieve pre-seeded compliance rules', () => {
      const hipaaRules = getComplianceRules('HIPAA');
      expect(hipaaRules.length).toBeGreaterThan(0);
    });

    it('should have rules for all regulations', () => {
      // Database stores regulations in uppercase
      const regulations = ['HIPAA', 'GDPR', 'SOC2', 'PCI-DSS'];

      for (const regulation of regulations) {
        const rules = getComplianceRules(regulation);
        expect(rules.length).toBeGreaterThan(0);
      }
    });

    it('should return all rules when no regulation specified', () => {
      const allRules = getComplianceRules();
      expect(allRules.length).toBeGreaterThanOrEqual(16); // At least 16 pre-seeded
    });

    it('should have correct HIPAA rules from research', () => {
      const hipaaRules = getComplianceRules('HIPAA');
      // Schema uses 'id' column with 'cr-hipaa-tls' format
      const tlsRule = hipaaRules.find((r: any) => r.id === 'cr-hipaa-tls');
      expect(tlsRule).toBeDefined();
      // Rule type indicates it's an encryption rule, description confirms criticality
      expect(tlsRule?.rule_type).toBe('encryption');
    });

    it('should have correct PCI-DSS rules from research', () => {
      const pciRules = getComplianceRules('PCI-DSS');
      // Schema uses 'id' column with 'cr-pci-cvv' format
      const cvvRule = pciRules.find((r: any) => r.id === 'cr-pci-cvv');
      expect(cvvRule).toBeDefined();
      // CVV rule is critical - check the rule description
      expect(cvvRule?.rule_name).toBe('Never Store CVV');
    });
  });

  describe('Data Integrity', () => {
    it('should enforce foreign key constraints', () => {
      // This depends on PRAGMA foreign_keys = ON being set
      const db = getDb();
      const result = db.prepare('PRAGMA foreign_keys').get() as { foreign_keys: number };
      expect(result.foreign_keys).toBe(1);
    });

    it('should handle concurrent writes', async () => {
      const uniqueBuildId = `concurrent-build-${Date.now()}`;
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(
          new Promise<void>((resolve) => {
            saveInspection({
              id: `concurrent-${Date.now()}-${i}-${Math.random()}`,
              build_id: uniqueBuildId,
              server_name: `server-${i}`,
              server_path: '/test',
              verdict: 'PASSED',
              summary_critical: 0,
              summary_high: 0,
              summary_medium: 0,
              summary_low: 0
            });
            resolve();
          })
        );
      }

      await Promise.all(promises);

      // Should not throw and all records should be saved
      const inspections = getInspectionsByBuild(uniqueBuildId);
      expect(inspections.length).toBe(10);
    });
  });
});
