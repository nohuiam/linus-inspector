/**
 * Compliance Rules - Research-backed from Perplexity documents
 *
 * HIPAA (Healthcare):
 * - Penalties: $100-$50K per violation, up to $1.5M annually
 * - TLS 1.2+ required, AES-256 encryption, 6-year audit logs
 *
 * GDPR (EU Data):
 * - Penalties: Up to €20M or 4% of global annual revenue
 * - Amazon fined €746M (2021)
 * - 72-hour breach notification, deletion includes backups
 *
 * SOC 2 (B2B SaaS):
 * - Failed audit = lost deals, $500K-$2M revenue impact
 * - MFA required, quarterly access reviews, annual DR drill
 *
 * PCI-DSS (Payment Data):
 * - Penalties: $5K-$100K monthly until compliant
 * - NEVER store CVV, tokenization required
 */

export interface ComplianceConfig {
  regulation: 'HIPAA' | 'GDPR' | 'SOC2' | 'PCI-DSS';
  requirements: {
    [key: string]: any;
  };
  penalties: string;
}

export const COMPLIANCE_CONFIGS: Record<string, ComplianceConfig> = {
  hipaa: {
    regulation: 'HIPAA',
    requirements: {
      tls_version: '1.2',
      encryption_at_rest: 'AES-256',
      audit_retention_years: 6,
      auto_logout_minutes: 15,
      baa_required: true,
      mfa_required: true,
      unique_user_ids: true
    },
    penalties: '$100-$50K per violation, up to $1.5M annually, criminal penalties for willful neglect'
  },
  gdpr: {
    regulation: 'GDPR',
    requirements: {
      cross_border_check: true,
      scc_required_for_us: true,
      breach_notification_hours: 72,
      deletion_cascade_to_backups: true,
      consent_explicit_unbundled: true,
      data_subject_rights_30_days: true
    },
    penalties: 'Up to €20M or 4% of global annual revenue (whichever higher)'
  },
  soc2: {
    regulation: 'SOC2',
    requirements: {
      mfa_required: true,
      change_approval_required: true,
      access_review_quarterly: true,
      dr_drill_annual: true,
      vendor_assessments: true,
      incident_response_plan: true
    },
    penalties: 'Audit failure = lost deals, $500K-$2M annual revenue impact'
  },
  'pci-dss': {
    regulation: 'PCI-DSS',
    requirements: {
      never_store_cvv: true,
      tokenization_required: true,
      network_segmentation: true,
      asv_scan_quarterly: true,
      tls_version: '1.2',
      encryption_at_rest: 'AES-256'
    },
    penalties: '$5K-$100K monthly fines until compliant, breach costs average $4M'
  }
};

export interface ComplianceRule {
  id: string;
  name: string;
  regulation: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  check: (code: string, regulation?: string) => ComplianceViolation[];
}

export interface ComplianceViolation {
  rule_id: string;
  regulation: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  location?: string;
  issue: string;
  remedy: string;
  penalty: string;
  auto_fixable: boolean;
}

export const COMPLIANCE_RULES: ComplianceRule[] = [
  // HIPAA Rules
  {
    id: 'hipaa-001',
    name: 'TLS Version',
    regulation: 'HIPAA',
    description: 'TLS 1.2+ required for all API calls (TLS 1.0/1.1 forbidden)',
    severity: 'CRITICAL',
    check: (code: string, regulation?: string): ComplianceViolation[] => {
      if (regulation && regulation.toUpperCase() !== 'HIPAA') return [];
      const violations: ComplianceViolation[] = [];

      const hasOldTLS = /tls.*1\.[01]|ssl.*3|tlsv1\.[01]/i.test(code);
      if (hasOldTLS) {
        violations.push({
          rule_id: 'hipaa-001',
          regulation: 'HIPAA',
          severity: 'CRITICAL',
          issue: 'TLS 1.0/1.1 or SSL 3.0 detected - forbidden under HIPAA',
          remedy: 'Use TLS 1.2 or higher for all connections',
          penalty: '$100-$50K per violation',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'hipaa-002',
    name: 'PHI Encryption at Rest',
    regulation: 'HIPAA',
    description: 'AES-256 required for databases storing PHI',
    severity: 'CRITICAL',
    check: (code: string, regulation?: string): ComplianceViolation[] => {
      if (regulation && regulation.toUpperCase() !== 'HIPAA') return [];
      const violations: ComplianceViolation[] = [];

      const storesPHI = /phi|patient|medical|health|diagnosis|treatment/i.test(code);
      const hasEncryption = /aes[_-]?256|encrypt.*rest|crypto/i.test(code);

      if (storesPHI && !hasEncryption) {
        violations.push({
          rule_id: 'hipaa-002',
          regulation: 'HIPAA',
          severity: 'CRITICAL',
          issue: 'PHI detected but no AES-256 encryption at rest',
          remedy: 'Encrypt all PHI with AES-256 before storing in database',
          penalty: '$100-$50K per violation',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'hipaa-003',
    name: 'Audit Log Retention',
    regulation: 'HIPAA',
    description: 'Audit logs must be retained for 6 years (immutable)',
    severity: 'HIGH',
    check: (code: string, regulation?: string): ComplianceViolation[] => {
      if (regulation && regulation.toUpperCase() !== 'HIPAA') return [];
      const violations: ComplianceViolation[] = [];

      const hasAuditLogs = /audit|log.*access|access.*log/i.test(code);
      const hasRetention = /6.*year|retention|archive|immutable/i.test(code);

      if (hasAuditLogs && !hasRetention) {
        violations.push({
          rule_id: 'hipaa-003',
          regulation: 'HIPAA',
          severity: 'HIGH',
          issue: 'Audit logging without 6-year retention configuration',
          remedy: 'Configure audit logs with 6-year retention and immutable storage',
          penalty: '$25K+ per violation',
          auto_fixable: false
        });
      }

      return violations;
    }
  },

  // GDPR Rules
  {
    id: 'gdpr-001',
    name: 'Cross-Border Transfer',
    regulation: 'GDPR',
    description: 'Transfers outside EU restricted - require SCCs or adequacy decision',
    severity: 'CRITICAL',
    check: (code: string, regulation?: string): ComplianceViolation[] => {
      if (regulation && regulation.toUpperCase() !== 'GDPR') return [];
      const violations: ComplianceViolation[] = [];

      const hasEUData = /eu|europe|gdpr|personal.*data/i.test(code);
      const transfersToUS = /us-east|us-west|america|\.com.*aws|azure.*us/i.test(code);
      const hasTransferMechanism = /scc|standard.*contract|adequacy|binding.*corporate|bcr/i.test(code);

      if (hasEUData && transfersToUS && !hasTransferMechanism) {
        violations.push({
          rule_id: 'gdpr-001',
          regulation: 'GDPR',
          severity: 'CRITICAL',
          issue: 'EU data transferred to US without legal transfer mechanism',
          remedy: 'Sign Standard Contractual Clauses (SCCs) with US data processors',
          penalty: 'Up to €20M or 4% of global revenue',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'gdpr-002',
    name: 'Breach Notification',
    regulation: 'GDPR',
    description: 'Notify DPA within 72 hours of breach detection',
    severity: 'HIGH',
    check: (code: string, regulation?: string): ComplianceViolation[] => {
      if (regulation && regulation.toUpperCase() !== 'GDPR') return [];
      const violations: ComplianceViolation[] = [];

      const hasBreachHandling = /breach|incident|security.*event/i.test(code);
      const has72HourNotification = /72.*hour|notification.*dpa|notify.*author/i.test(code);

      if (hasBreachHandling && !has72HourNotification) {
        violations.push({
          rule_id: 'gdpr-002',
          regulation: 'GDPR',
          severity: 'HIGH',
          issue: 'Breach handling without 72-hour DPA notification workflow',
          remedy: 'Implement breach notification workflow with 72-hour SLA to DPA',
          penalty: '€10M or 2% of global revenue',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'gdpr-003',
    name: 'Right to Erasure',
    regulation: 'GDPR',
    description: 'Deletion must cascade to backups',
    severity: 'HIGH',
    check: (code: string, regulation?: string): ComplianceViolation[] => {
      if (regulation && regulation.toUpperCase() !== 'GDPR') return [];
      const violations: ComplianceViolation[] = [];

      const hasDeletion = /delete|erase|remove.*user|gdpr.*request/i.test(code);
      const cascadesToBackups = /backup.*delete|delete.*backup|cascade.*backup/i.test(code);

      if (hasDeletion && !cascadesToBackups) {
        violations.push({
          rule_id: 'gdpr-003',
          regulation: 'GDPR',
          severity: 'HIGH',
          issue: 'Data deletion does not cascade to backups',
          remedy: 'Implement deletion that propagates to all backup systems',
          penalty: '€20M or 4% of global revenue',
          auto_fixable: false
        });
      }

      return violations;
    }
  },

  // SOC 2 Rules
  {
    id: 'soc2-001',
    name: 'MFA Required',
    regulation: 'SOC2',
    description: 'MFA required for all users, especially admins',
    severity: 'HIGH',
    check: (code: string, regulation?: string): ComplianceViolation[] => {
      if (regulation && regulation.toUpperCase() !== 'SOC2') return [];
      const violations: ComplianceViolation[] = [];

      const hasAuth = /auth|login|signin|password/i.test(code);
      const hasMFA = /mfa|2fa|two[_-]?factor|totp|authenticator/i.test(code);

      if (hasAuth && !hasMFA) {
        violations.push({
          rule_id: 'soc2-001',
          regulation: 'SOC2',
          severity: 'HIGH',
          issue: 'Authentication without MFA enforcement',
          remedy: 'Enforce MFA for all users, no exceptions for admins',
          penalty: 'Critical finding, audit failure',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'soc2-002',
    name: 'Change Approval',
    regulation: 'SOC2',
    description: 'All production changes via documented ticket',
    severity: 'MEDIUM',
    check: (code: string, regulation?: string): ComplianceViolation[] => {
      if (regulation && regulation.toUpperCase() !== 'SOC2') return [];
      const violations: ComplianceViolation[] = [];

      const hasDeployment = /deploy|release|production|ci.*cd/i.test(code);
      const hasApproval = /approv|review|ticket|jira|pr.*review/i.test(code);

      if (hasDeployment && !hasApproval) {
        violations.push({
          rule_id: 'soc2-002',
          regulation: 'SOC2',
          severity: 'MEDIUM',
          issue: 'Deployment without change approval workflow',
          remedy: 'Require ticket/PR approval before production deployment',
          penalty: 'Control gap finding',
          auto_fixable: false
        });
      }

      return violations;
    }
  },

  // PCI-DSS Rules
  {
    id: 'pci-001',
    name: 'Never Store CVV',
    regulation: 'PCI-DSS',
    description: 'CVV/CVC must NEVER be stored after authorization',
    severity: 'CRITICAL',
    check: (code: string, regulation?: string): ComplianceViolation[] => {
      if (regulation && regulation.toUpperCase() !== 'PCI-DSS') return [];
      const violations: ComplianceViolation[] = [];

      const storesCVV = /cvv|cvc|security.*code|card.*code/i.test(code);
      const stores = /save|store|insert|database|persist/i.test(code);

      if (storesCVV && stores) {
        violations.push({
          rule_id: 'pci-001',
          regulation: 'PCI-DSS',
          severity: 'CRITICAL',
          issue: 'CVV/CVC storage detected - STRICTLY FORBIDDEN',
          remedy: 'NEVER store CVV after authorization - use tokenization',
          penalty: '$5K-$100K monthly fines',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'pci-002',
    name: 'Tokenization Required',
    regulation: 'PCI-DSS',
    description: 'Use tokenization for card data (Stripe/Braintree)',
    severity: 'HIGH',
    check: (code: string, regulation?: string): ComplianceViolation[] => {
      if (regulation && regulation.toUpperCase() !== 'PCI-DSS') return [];
      const violations: ComplianceViolation[] = [];

      const handlesCardData = /card.*number|pan|credit.*card/i.test(code);
      const usesTokenization = /token|stripe|braintree|square|adyen/i.test(code);

      if (handlesCardData && !usesTokenization) {
        violations.push({
          rule_id: 'pci-002',
          regulation: 'PCI-DSS',
          severity: 'HIGH',
          issue: 'Card data handling without tokenization',
          remedy: 'Use Stripe/Braintree tokenization - let them handle PCI compliance',
          penalty: '$5K-$100K monthly fines',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'pci-003',
    name: 'Network Segmentation',
    regulation: 'PCI-DSS',
    description: 'Cardholder Data Environment (CDE) must be isolated',
    severity: 'HIGH',
    check: (code: string, regulation?: string): ComplianceViolation[] => {
      if (regulation && regulation.toUpperCase() !== 'PCI-DSS') return [];
      const violations: ComplianceViolation[] = [];

      const handlesCDE = /payment|card|pan|checkout/i.test(code);
      const hasSegmentation = /vpc|subnet|firewall|isolated|segmented|cde/i.test(code);

      if (handlesCDE && !hasSegmentation) {
        violations.push({
          rule_id: 'pci-003',
          regulation: 'PCI-DSS',
          severity: 'HIGH',
          issue: 'Payment handling without network segmentation',
          remedy: 'Isolate CDE in separate VPC with firewall rules',
          penalty: 'Full infrastructure in PCI scope',
          auto_fixable: false
        });
      }

      return violations;
    }
  }
];

export function checkComplianceRules(code: string, regulation?: string): ComplianceViolation[] {
  const violations: ComplianceViolation[] = [];

  for (const rule of COMPLIANCE_RULES) {
    violations.push(...rule.check(code, regulation));
  }

  return violations;
}

export function getComplianceConfig(regulation: string): ComplianceConfig | null {
  return COMPLIANCE_CONFIGS[regulation.toLowerCase()] || null;
}

export function getAllRegulations(): string[] {
  return Object.keys(COMPLIANCE_CONFIGS);
}
