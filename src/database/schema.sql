-- Linus Inspector Database Schema
-- Stores inspection results, issues, and auto-fix history

-- Inspection runs
CREATE TABLE IF NOT EXISTS inspections (
  id TEXT PRIMARY KEY,
  build_id TEXT NOT NULL,
  server_name TEXT NOT NULL,
  server_type TEXT,
  industry TEXT,
  mode TEXT NOT NULL CHECK (mode IN ('pre-build', 'build', 'runtime')),
  verdict TEXT NOT NULL CHECK (verdict IN ('PASSED', 'BLOCKED', 'WARNING')),
  summary_critical INTEGER DEFAULT 0,
  summary_high INTEGER DEFAULT 0,
  summary_medium INTEGER DEFAULT 0,
  summary_low INTEGER DEFAULT 0,
  auto_fixes_available INTEGER DEFAULT 0,
  auto_fixes_applied INTEGER DEFAULT 0,
  duration_ms INTEGER,
  created_at TEXT DEFAULT (datetime('now')),
  completed_at TEXT
);

CREATE INDEX idx_inspections_build ON inspections(build_id);
CREATE INDEX idx_inspections_server ON inspections(server_name);
CREATE INDEX idx_inspections_verdict ON inspections(verdict);
CREATE INDEX idx_inspections_created ON inspections(created_at);

-- Individual issues found during inspection
CREATE TABLE IF NOT EXISTS inspection_issues (
  id TEXT PRIMARY KEY,
  inspection_id TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  category TEXT NOT NULL,
  location TEXT,
  issue TEXT NOT NULL,
  remedy TEXT,
  auto_fixable INTEGER DEFAULT 0,
  auto_fixed INTEGER DEFAULT 0,
  fix_applied_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (inspection_id) REFERENCES inspections(id) ON DELETE CASCADE
);

CREATE INDEX idx_issues_inspection ON inspection_issues(inspection_id);
CREATE INDEX idx_issues_severity ON inspection_issues(severity);
CREATE INDEX idx_issues_category ON inspection_issues(category);

-- Pre-build API inspection results
CREATE TABLE IF NOT EXISTS api_inspections (
  id TEXT PRIMARY KEY,
  vendor TEXT NOT NULL,
  inspection_timestamp TEXT DEFAULT (datetime('now')),
  base_url TEXT,
  auth_type TEXT,
  auth_scopes TEXT, -- JSON array
  rate_limits TEXT, -- JSON object
  endpoints TEXT, -- JSON array
  custom_objects TEXT, -- JSON array
  webhooks_supported INTEGER DEFAULT 0,
  webhook_url TEXT,
  recommendations TEXT, -- JSON array
  raw_response TEXT -- Full API probe response
);

CREATE INDEX idx_api_inspections_vendor ON api_inspections(vendor);
CREATE INDEX idx_api_inspections_timestamp ON api_inspections(inspection_timestamp);

-- Connection test results
CREATE TABLE IF NOT EXISTS connection_tests (
  id TEXT PRIMARY KEY,
  inspection_id TEXT,
  server_path TEXT NOT NULL,
  test_mode TEXT CHECK (test_mode IN ('auth', 'full', 'quick')),
  use_sandbox INTEGER DEFAULT 1,
  verdict TEXT NOT NULL CHECK (verdict IN ('PASS', 'FAIL', 'PARTIAL')),
  tests TEXT NOT NULL, -- JSON array of test results
  performance TEXT, -- JSON object with latency stats
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (inspection_id) REFERENCES inspections(id) ON DELETE SET NULL
);

CREATE INDEX idx_connection_tests_inspection ON connection_tests(inspection_id);
CREATE INDEX idx_connection_tests_verdict ON connection_tests(verdict);

-- Prompt inspection results
CREATE TABLE IF NOT EXISTS prompt_inspections (
  id TEXT PRIMARY KEY,
  prompt_id TEXT,
  prompt_content TEXT NOT NULL,
  verdict TEXT NOT NULL CHECK (verdict IN ('PASSED', 'NEEDS_REVISION', 'BLOCKED')),
  safety_score REAL,
  token_count INTEGER,
  estimated_efficient_tokens INTEGER,
  clarity_score REAL,
  issues TEXT, -- JSON array
  anthropic_compliance TEXT, -- JSON object with passes/fails
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_prompt_inspections_verdict ON prompt_inspections(verdict);

-- Skill validation results
CREATE TABLE IF NOT EXISTS skill_validations (
  id TEXT PRIMARY KEY,
  skill_path TEXT NOT NULL,
  skill_name TEXT,
  verdict TEXT NOT NULL CHECK (verdict IN ('PASSED', 'NEEDS_REVISION', 'BLOCKED')),
  structure_valid INTEGER DEFAULT 0,
  description_valid INTEGER DEFAULT 0,
  triggers_valid INTEGER DEFAULT 0,
  instructions_valid INTEGER DEFAULT 0,
  examples_present INTEGER DEFAULT 0,
  safety_valid INTEGER DEFAULT 0,
  issues TEXT, -- JSON array
  anthropic_compliance TEXT, -- JSON object
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_skill_validations_verdict ON skill_validations(verdict);
CREATE INDEX idx_skill_validations_path ON skill_validations(skill_path);

-- Ecosystem integration checks
CREATE TABLE IF NOT EXISTS integration_checks (
  id TEXT PRIMARY KEY,
  inspection_id TEXT,
  server_path TEXT NOT NULL,
  verdict TEXT NOT NULL CHECK (verdict IN ('PASS', 'FAIL', 'PARTIAL')),
  interlock_valid INTEGER DEFAULT 0,
  interlock_port INTEGER,
  peer_connectivity TEXT, -- JSON object
  signal_health TEXT, -- JSON object
  mcp_tools TEXT, -- JSON array
  health_endpoint_status INTEGER,
  issues TEXT, -- JSON array
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (inspection_id) REFERENCES inspections(id) ON DELETE SET NULL
);

CREATE INDEX idx_integration_checks_inspection ON integration_checks(inspection_id);
CREATE INDEX idx_integration_checks_verdict ON integration_checks(verdict);

-- Auto-fix history
CREATE TABLE IF NOT EXISTS auto_fixes (
  id TEXT PRIMARY KEY,
  issue_id TEXT NOT NULL,
  inspection_id TEXT NOT NULL,
  fix_type TEXT NOT NULL,
  original_content TEXT,
  fixed_content TEXT,
  file_path TEXT,
  success INTEGER DEFAULT 0,
  error_message TEXT,
  applied_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (issue_id) REFERENCES inspection_issues(id) ON DELETE CASCADE,
  FOREIGN KEY (inspection_id) REFERENCES inspections(id) ON DELETE CASCADE
);

CREATE INDEX idx_auto_fixes_issue ON auto_fixes(issue_id);
CREATE INDEX idx_auto_fixes_inspection ON auto_fixes(inspection_id);

-- Vendor-specific configurations (rate limits, auth patterns, etc.)
CREATE TABLE IF NOT EXISTS vendor_configs (
  id TEXT PRIMARY KEY,
  vendor TEXT NOT NULL UNIQUE,
  rate_limit_value INTEGER,
  rate_limit_window_ms INTEGER,
  rate_limit_type TEXT,
  auth_type TEXT,
  auth_token_expiry_minutes INTEGER,
  auth_refresh_buffer_minutes INTEGER,
  pagination_type TEXT,
  pagination_gotchas TEXT, -- JSON array
  webhook_timeout_ms INTEGER,
  known_issues TEXT, -- JSON array
  recommendations TEXT, -- JSON array
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX idx_vendor_configs_vendor ON vendor_configs(vendor);

-- Pre-seed vendor configurations from research
INSERT OR REPLACE INTO vendor_configs (id, vendor, rate_limit_value, rate_limit_window_ms, rate_limit_type, auth_type, auth_token_expiry_minutes, auth_refresh_buffer_minutes, pagination_type, pagination_gotchas, webhook_timeout_ms, known_issues, recommendations) VALUES
  ('vc-salesforce', 'salesforce', 100, 20000, 'leaky_bucket', 'oauth2', 90, 5, 'cursor', '["Governor limits are hard caps", "Bulk API for >10K records"]', 10000, '["SOQL non-selective queries timeout", "Sandbox has different limits than production"]', '["Query outside loops", "Use indexed fields", "Batch DML operations"]'),
  ('vc-hubspot', 'hubspot', 190, 10000, 'sliding_window', 'private_app', 360, 5, 'cursor', '["Pagination returns duplicates - MUST deduplicate", "Offset pagination deprecated"]', 10000, '["Webhook delays up to 30 minutes", "Custom objects require explicit schema mapping"]', '["Use cursor pagination", "Implement deduplication", "Webhook + polling hybrid"]'),
  ('vc-stripe', 'stripe', 100, 1000, 'token_bucket', 'api_key', NULL, NULL, 'cursor', '["Thin events - always fetch fresh data"]', 10000, '["Webhook signature validation required", "Events may arrive out of order"]', '["Validate webhook signatures", "Use idempotency keys", "Fetch fresh data on webhook"]'),
  ('vc-snowflake', 'snowflake', 30, 60000, 'fixed_window', 'jwt', 60, 5, 'offset', '["JWT expires in 1 hour"]', 30000, '["Cortex API has separate limits", "Network policies can block"]', '["Refresh JWT every 50 minutes", "Check network policies"]'),
  ('vc-zendesk', 'zendesk', 700, 60000, 'sliding_window', 'api_token', NULL, NULL, 'cursor', '["Deep pagination throttled to 10 req/min", "Cursor preferred over offset"]', 10000, '["Deep pagination severely throttled"]', '["Use cursor pagination", "Respect Retry-After header"]'),
  ('vc-slack', 'slack', 50, 60000, 'tier_based', 'oauth2', NULL, NULL, 'cursor', '["Rate limits tier-based"]', 3000, '["Non-Marketplace apps limited to 1 req/min", "May 2025 rate limit changes"]', '["Get Marketplace approval", "Use tier-aware rate limiting"]'),
  ('vc-quickbooks', 'quickbooks', 500, 60000, 'sliding_window', 'oauth2', 60, 5, 'offset', '["Max 10 concurrent requests"]', 10000, '["Reauth required after 100 days", "Concurrent request limits"]', '["Implement 100-day reconnection flow", "Limit concurrent requests to 10"]'),
  ('vc-shopify', 'shopify', 4, 1000, 'leaky_bucket', 'oauth2', NULL, NULL, 'cursor', '["GraphQL uses point system - costs unpredictable", "REST uses leaky bucket"]', 10000, '["GraphQL point costs vary by query complexity"]', '["Track GraphQL points", "Use REST for predictable costs"]'),
  ('vc-servicenow', 'servicenow', 0, 0, 'user_defined', 'oauth2', NULL, NULL, 'offset', '["No default rate limits - must configure"]', 30000, '["Rate limits must be configured by admin", "OAuth scopes must be defined"]', '["Configure rate limits in instance", "Define OAuth scopes explicitly"]'),
  ('vc-microsoft365', 'microsoft365', 130000, 10000, 'multi_layer', 'oauth2', 60, 5, 'cursor', '["Multi-layer throttling - service-specific limits apply"]', 10000, '["Different services have different limits", "Teams API has separate throttling"]', '["Handle service-specific rate limits", "Implement multi-layer backoff"]');

-- Compliance rule configurations
CREATE TABLE IF NOT EXISTS compliance_rules (
  id TEXT PRIMARY KEY,
  regulation TEXT NOT NULL,
  rule_name TEXT NOT NULL,
  rule_type TEXT NOT NULL,
  required_value TEXT,
  description TEXT,
  penalty_info TEXT,
  check_function TEXT, -- Function name to call for validation
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_compliance_rules_regulation ON compliance_rules(regulation);

-- Pre-seed compliance rules from research
INSERT OR REPLACE INTO compliance_rules (id, regulation, rule_name, rule_type, required_value, description, penalty_info, check_function) VALUES
  -- HIPAA Rules
  ('cr-hipaa-tls', 'HIPAA', 'TLS Version', 'encryption', '1.2', 'TLS 1.2+ required for all API calls (TLS 1.0/1.1 forbidden)', '$100-$50K per violation', 'checkTlsVersion'),
  ('cr-hipaa-aes', 'HIPAA', 'Encryption at Rest', 'encryption', 'AES-256', 'AES-256 required for databases storing PHI', '$100-$50K per violation', 'checkEncryptionAtRest'),
  ('cr-hipaa-audit', 'HIPAA', 'Audit Log Retention', 'logging', '6 years', 'Audit logs must be retained for 6 years (immutable)', '$25K+ per violation', 'checkAuditRetention'),
  ('cr-hipaa-logout', 'HIPAA', 'Auto Logout', 'access', '15 minutes', 'Auto-logout required after 15 minutes of inactivity', '$50K per violation', 'checkAutoLogout'),
  ('cr-hipaa-baa', 'HIPAA', 'BAA Required', 'contract', 'true', 'Business Associate Agreement required before PHI access', '$1.5M max annual', 'checkBaaPresent'),

  -- GDPR Rules
  ('cr-gdpr-transfer', 'GDPR', 'Cross-Border Transfer', 'data_residency', 'SCCs or adequacy', 'Transfers outside EU restricted - require SCCs or adequacy decision', '€20M or 4% revenue', 'checkCrossBorderTransfer'),
  ('cr-gdpr-breach', 'GDPR', 'Breach Notification', 'incident', '72 hours', 'Notify DPA within 72 hours of breach detection', '€10M or 2% revenue', 'checkBreachNotification'),
  ('cr-gdpr-deletion', 'GDPR', 'Right to Erasure', 'data_rights', 'including backups', 'Must delete data from backups too on erasure request', '€20M or 4% revenue', 'checkDeletionCascade'),
  ('cr-gdpr-consent', 'GDPR', 'Explicit Consent', 'consent', 'unbundled', 'Consent must be explicit and unbundled', '€10M or 2% revenue', 'checkExplicitConsent'),

  -- SOC 2 Rules
  ('cr-soc2-mfa', 'SOC2', 'MFA Required', 'access', 'all users', 'MFA required for all users, especially admins', 'Audit failure', 'checkMfaRequired'),
  ('cr-soc2-access', 'SOC2', 'Access Reviews', 'access', 'quarterly', 'Quarterly access reviews required', 'Control gap', 'checkAccessReviews'),
  ('cr-soc2-change', 'SOC2', 'Change Approval', 'change_mgmt', 'documented', 'All production changes via documented ticket', 'Critical finding', 'checkChangeApproval'),
  ('cr-soc2-dr', 'SOC2', 'DR Testing', 'disaster_recovery', 'annual', 'Annual DR drill required', 'Control deficiency', 'checkDrTesting'),

  -- PCI-DSS Rules
  ('cr-pci-cvv', 'PCI-DSS', 'Never Store CVV', 'data', 'forbidden', 'CVV/CVC must NEVER be stored after authorization', '$5K-$100K monthly', 'checkCvvStorage'),
  ('cr-pci-token', 'PCI-DSS', 'Tokenization', 'data', 'required', 'Use tokenization for card data (Stripe/Braintree)', '$5K-$100K monthly', 'checkTokenization'),
  ('cr-pci-segment', 'PCI-DSS', 'Network Segmentation', 'network', 'CDE isolated', 'Cardholder Data Environment must be isolated', 'Full scope expansion', 'checkNetworkSegmentation'),
  ('cr-pci-scan', 'PCI-DSS', 'Vulnerability Scans', 'security', 'quarterly', 'Quarterly ASV scans required', 'Failed audit', 'checkVulnScans');
