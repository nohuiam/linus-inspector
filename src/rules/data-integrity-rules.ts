/**
 * Data Integrity Rules - Research-backed from Perplexity documents
 *
 * Data inconsistency: 8-10% of issues BUT highest cost
 * Mean time to detect: 24 HOURS (silent corruption!)
 * Mean time to resolve: 8 hours
 * Revenue impact: $50K-$500K per incident
 *
 * Idempotency issues: 5-10% of issues
 * Mean time to detect: 48 HOURS
 * Mean time to resolve: 12 hours
 * Revenue impact: $100K+
 *
 * Key patterns:
 * - Eventual consistency handling
 * - Idempotency key management
 * - Pagination deduplication (HubSpot returns duplicates!)
 * - Reconciliation jobs
 */

export interface DataIntegrityConfig {
  eventual_consistency: {
    read_after_write_buffer_ms: number;
    reconciliation_schedule: string;
    conflict_resolution: 'source_wins' | 'latest_wins' | 'manual';
  };
  idempotency: {
    key_storage: 'database' | 'cache' | 'memory';
    key_ttl_hours: number;
    payload_hash: boolean;
    concurrent_request_handling: 'queue' | 'reject' | 'dedupe';
  };
  pagination: {
    deduplication: boolean;
    cursor_preferred: boolean;
    offset_deprecated_warning: boolean;
  };
}

export const DEFAULT_DATA_INTEGRITY_CONFIG: DataIntegrityConfig = {
  eventual_consistency: {
    read_after_write_buffer_ms: 5000,
    reconciliation_schedule: 'hourly',
    conflict_resolution: 'source_wins'
  },
  idempotency: {
    key_storage: 'database',
    key_ttl_hours: 24,
    payload_hash: true,
    concurrent_request_handling: 'queue'
  },
  pagination: {
    deduplication: true,
    cursor_preferred: true,
    offset_deprecated_warning: true
  }
};

export interface DataIntegrityRule {
  id: string;
  name: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  check: (code: string, vendor?: string) => DataIntegrityViolation[];
}

export interface DataIntegrityViolation {
  rule_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  location?: string;
  issue: string;
  remedy: string;
  auto_fixable: boolean;
}

export const DATA_INTEGRITY_RULES: DataIntegrityRule[] = [
  {
    id: 'di-001',
    name: 'No Idempotency Keys',
    description: 'Create/update operations MUST use idempotency keys',
    severity: 'CRITICAL',
    check: (code: string): DataIntegrityViolation[] => {
      const violations: DataIntegrityViolation[] = [];

      const hasWriteOps = /post|put|patch|create|update|insert/i.test(code);
      const hasIdempotency = /idempoten|request[_-]?id|transaction[_-]?id|unique.*key/i.test(code);

      if (hasWriteOps && !hasIdempotency) {
        violations.push({
          rule_id: 'di-001',
          severity: 'CRITICAL',
          issue: 'Write operations without idempotency keys - duplicates possible',
          remedy: 'Generate UUID idempotency key per operation, store in DB with 24-hour TTL',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'di-002',
    name: 'No Reconciliation Job',
    description: 'Eventual consistency requires periodic reconciliation',
    severity: 'HIGH',
    check: (code: string): DataIntegrityViolation[] => {
      const violations: DataIntegrityViolation[] = [];

      const hasSyncing = /sync|integration|webhook|event/i.test(code);
      const hasReconciliation = /reconcil|verify|check.*consistency|hourly.*job|cron/i.test(code);

      if (hasSyncing && !hasReconciliation) {
        violations.push({
          rule_id: 'di-002',
          severity: 'HIGH',
          issue: 'Data syncing without reconciliation job - drift undetected for 24+ hours',
          remedy: 'Implement hourly reconciliation job to detect and fix drift',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'di-003',
    name: 'HubSpot Pagination Deduplication',
    description: 'HubSpot pagination returns duplicates - MUST deduplicate',
    severity: 'CRITICAL',
    check: (code: string, vendor?: string): DataIntegrityViolation[] => {
      const violations: DataIntegrityViolation[] = [];

      if (vendor !== 'hubspot') return violations;

      const hasPagination = /page|offset|cursor|next|after/i.test(code);
      const hasDeduplication = /dedup|unique|set|seen|already.*processed/i.test(code);

      if (hasPagination && !hasDeduplication) {
        violations.push({
          rule_id: 'di-003',
          severity: 'CRITICAL',
          issue: 'HubSpot pagination returns duplicates - no deduplication detected',
          remedy: 'Track seen record IDs and filter duplicates from paginated results',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'di-004',
    name: 'Offset Pagination Deprecated',
    description: 'Offset pagination is deprecated - use cursor-based',
    severity: 'MEDIUM',
    check: (code: string, vendor?: string): DataIntegrityViolation[] => {
      const violations: DataIntegrityViolation[] = [];

      const usesOffset = /offset|skip|page[_-]?num/i.test(code);

      if (usesOffset) {
        violations.push({
          rule_id: 'di-004',
          severity: 'MEDIUM',
          issue: 'Offset pagination detected - may cause duplicates/missed records',
          remedy: 'Use cursor-based pagination (after/cursor parameter) where available',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'di-005',
    name: 'No Read-After-Write Buffer',
    description: 'Must wait for eventual consistency after writes',
    severity: 'MEDIUM',
    check: (code: string): DataIntegrityViolation[] => {
      const violations: DataIntegrityViolation[] = [];

      const hasWriteThenRead = /create.*then.*get|post.*get|update.*fetch/i.test(code);
      const hasBuffer = /wait|delay|timeout|setTimeout|eventual/i.test(code);

      if (hasWriteThenRead && !hasBuffer) {
        violations.push({
          rule_id: 'di-005',
          severity: 'MEDIUM',
          issue: 'Read immediately after write - may get stale data',
          remedy: 'Add 5-second buffer after writes before reading (eventual consistency)',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'di-006',
    name: 'No Conflict Resolution',
    description: 'Must handle data conflicts in bidirectional sync',
    severity: 'HIGH',
    check: (code: string): DataIntegrityViolation[] => {
      const violations: DataIntegrityViolation[] = [];

      const hasBidirectionalSync = /bidirectional|two[_-]?way|sync.*both/i.test(code);
      const hasConflictResolution = /conflict|merge|resolution|last[_-]?write|source.*win/i.test(code);

      if (hasBidirectionalSync && !hasConflictResolution) {
        violations.push({
          rule_id: 'di-006',
          severity: 'HIGH',
          issue: 'Bidirectional sync without conflict resolution strategy',
          remedy: 'Implement conflict resolution: source_wins, latest_wins, or manual merge',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'di-007',
    name: 'Type Coercion Risk',
    description: 'Data transformations must preserve types',
    severity: 'MEDIUM',
    check: (code: string): DataIntegrityViolation[] => {
      const violations: DataIntegrityViolation[] = [];

      const hasTransformation = /transform|map|convert|parse/i.test(code);
      const hasTypeValidation = /typeof|instanceof|schema|validate|zod|yup/i.test(code);

      if (hasTransformation && !hasTypeValidation) {
        violations.push({
          rule_id: 'di-007',
          severity: 'MEDIUM',
          issue: 'Data transformation without type validation',
          remedy: 'Add type validation (Zod, Yup) to transformations to prevent data loss',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'di-008',
    name: 'No Null/Empty Handling',
    description: 'Must handle null and empty values explicitly',
    severity: 'MEDIUM',
    check: (code: string): DataIntegrityViolation[] => {
      const violations: DataIntegrityViolation[] = [];

      const hasDataProcessing = /map|filter|reduce|forEach|\.data/i.test(code);
      const hasNullHandling = /null|undefined|\?\.|optional|default|fallback/i.test(code);

      if (hasDataProcessing && !hasNullHandling) {
        violations.push({
          rule_id: 'di-008',
          severity: 'MEDIUM',
          issue: 'Data processing without null/empty value handling',
          remedy: 'Add explicit null checks, optional chaining (?.), and default values',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'di-009',
    name: 'Salesforce Governor Limits',
    description: 'Salesforce has hard limits - SOQL outside loops, batch DML',
    severity: 'CRITICAL',
    check: (code: string, vendor?: string): DataIntegrityViolation[] => {
      const violations: DataIntegrityViolation[] = [];

      if (vendor !== 'salesforce') return violations;

      // Check for SOQL in loops (very common mistake)
      const soqlInLoop = /for.*soql|while.*query|loop.*select/i.test(code);
      if (soqlInLoop) {
        violations.push({
          rule_id: 'di-009',
          severity: 'CRITICAL',
          location: 'SOQL query in loop',
          issue: 'SOQL query inside loop will hit 100-query governor limit',
          remedy: 'Move SOQL query OUTSIDE loop, query all records first, then iterate',
          auto_fixable: false
        });
      }

      // Check for unbatched DML
      const unbatchedDML = /for.*insert|for.*update|while.*save/i.test(code);
      if (unbatchedDML) {
        violations.push({
          rule_id: 'di-009',
          severity: 'CRITICAL',
          location: 'DML in loop',
          issue: 'DML operation inside loop will hit 150-statement governor limit',
          remedy: 'Collect records in list, then batch insert/update outside loop',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'di-010',
    name: 'No Audit Trail',
    description: 'Data changes must be logged for debugging',
    severity: 'LOW',
    check: (code: string): DataIntegrityViolation[] => {
      const violations: DataIntegrityViolation[] = [];

      const hasDataChanges = /create|update|delete|insert|modify/i.test(code);
      const hasAuditLog = /audit|log.*change|history|track.*change/i.test(code);

      if (hasDataChanges && !hasAuditLog) {
        violations.push({
          rule_id: 'di-010',
          severity: 'LOW',
          issue: 'Data changes without audit logging',
          remedy: 'Log before/after values for all data changes (aids debugging)',
          auto_fixable: true
        });
      }

      return violations;
    }
  }
];

export function checkDataIntegrityRules(code: string, vendor?: string): DataIntegrityViolation[] {
  const violations: DataIntegrityViolation[] = [];

  for (const rule of DATA_INTEGRITY_RULES) {
    violations.push(...rule.check(code, vendor));
  }

  return violations;
}

export function getDefaultDataIntegrityConfig(): DataIntegrityConfig {
  return { ...DEFAULT_DATA_INTEGRITY_CONFIG };
}
