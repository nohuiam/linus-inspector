/**
 * Webhook Rules - Research-backed from Perplexity documents
 *
 * Webhook delivery failures: 12-20% of issues
 * Mean time to detect: 1 hour
 * Mean time to resolve: 30 minutes
 * Revenue impact: $10K-$100K per incident
 *
 * Key findings from research:
 * - Carrier APIs: 20-30% retry rate (4-6x worse than SaaS)
 * - "Webhook amnesia": systems accept events but fail to deliver 12-18%
 * - Black Friday: 3 platforms had complete webhook outages (2-6 hours)
 * - HubSpot webhook delays up to 30 minutes during peak
 *
 * Critical Pattern: Webhook + Polling Hybrid
 * - Webhooks as hints, polling as source of truth
 * - Never trust webhook payload - always fetch fresh data
 */

export interface WebhookConfig {
  timeout_ms: number;
  signature_validation: boolean;
  signature_header?: string;
  polling_fallback_minutes: number;
  dedup_window_hours: number;
  thin_events: boolean; // Stripe-style: event is just notification, fetch full data
}

export const VENDOR_WEBHOOK_CONFIGS: Record<string, WebhookConfig> = {
  salesforce: {
    timeout_ms: 10000,
    signature_validation: true,
    polling_fallback_minutes: 5,
    dedup_window_hours: 24,
    thin_events: false
  },
  hubspot: {
    timeout_ms: 10000,
    signature_validation: true,
    signature_header: 'X-HubSpot-Signature',
    polling_fallback_minutes: 5, // Webhooks can be delayed 30 min!
    dedup_window_hours: 24,
    thin_events: false
  },
  stripe: {
    timeout_ms: 10000,
    signature_validation: true,
    signature_header: 'Stripe-Signature',
    polling_fallback_minutes: 5,
    dedup_window_hours: 24,
    thin_events: true // IMPORTANT: Stripe events are thin - must fetch fresh data
  },
  shopify: {
    timeout_ms: 10000,
    signature_validation: true,
    signature_header: 'X-Shopify-Hmac-SHA256',
    polling_fallback_minutes: 5,
    dedup_window_hours: 24,
    thin_events: false
  },
  quickbooks: {
    timeout_ms: 10000,
    signature_validation: true,
    polling_fallback_minutes: 5,
    dedup_window_hours: 24,
    thin_events: false
  },
  zendesk: {
    timeout_ms: 10000,
    signature_validation: true,
    polling_fallback_minutes: 5,
    dedup_window_hours: 24,
    thin_events: false
  },
  slack: {
    timeout_ms: 3000, // Slack expects response within 3 seconds!
    signature_validation: true,
    signature_header: 'X-Slack-Signature',
    polling_fallback_minutes: 5,
    dedup_window_hours: 24,
    thin_events: false
  }
};

export interface WebhookRule {
  id: string;
  name: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  check: (code: string, vendor?: string) => WebhookViolation[];
}

export interface WebhookViolation {
  rule_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  location?: string;
  issue: string;
  remedy: string;
  auto_fixable: boolean;
}

export const WEBHOOK_RULES: WebhookRule[] = [
  {
    id: 'wh-001',
    name: 'No Polling Fallback',
    description: 'Webhooks MUST have polling fallback - 20-30% failure rate',
    severity: 'CRITICAL',
    check: (code: string): WebhookViolation[] => {
      const violations: WebhookViolation[] = [];

      const hasWebhook = /webhook|event|notification|subscribe/i.test(code);
      const hasPolling = /poll|interval|cron|schedule|setInterval|periodic/i.test(code);

      if (hasWebhook && !hasPolling) {
        violations.push({
          rule_id: 'wh-001',
          severity: 'CRITICAL',
          issue: 'Webhook-only architecture without polling fallback - 20-30% of events may be lost',
          remedy: 'Implement webhook + polling hybrid: webhooks as hints, polling every 5 minutes as backup',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'wh-002',
    name: 'No Signature Validation',
    description: 'Webhook signatures MUST be validated to prevent spoofing',
    severity: 'CRITICAL',
    check: (code: string, vendor?: string): WebhookViolation[] => {
      const violations: WebhookViolation[] = [];

      const hasWebhook = /webhook|event.*handler|notification.*handler/i.test(code);
      const hasSignatureValidation = /signature|hmac|verify|validate.*header|crypto/i.test(code);

      if (hasWebhook && !hasSignatureValidation) {
        const config = vendor ? VENDOR_WEBHOOK_CONFIGS[vendor] : null;
        violations.push({
          rule_id: 'wh-002',
          severity: 'CRITICAL',
          issue: 'Webhook handler without signature validation - vulnerable to spoofing',
          remedy: config?.signature_header
            ? `Validate ${config.signature_header} header using vendor secret`
            : 'Implement webhook signature validation using HMAC-SHA256',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'wh-003',
    name: 'Trusting Webhook Payload',
    description: 'Must fetch fresh data from API, not trust webhook payload',
    severity: 'HIGH',
    check: (code: string, vendor?: string): WebhookViolation[] => {
      const violations: WebhookViolation[] = [];

      const hasWebhook = /webhook|event.*handler/i.test(code);
      const fetchesOnWebhook = /webhook.*fetch|event.*get|fetch.*after|refresh|reload/i.test(code);

      if (hasWebhook && !fetchesOnWebhook) {
        const config = vendor ? VENDOR_WEBHOOK_CONFIGS[vendor] : null;
        const severity = config?.thin_events ? 'CRITICAL' : 'HIGH';

        violations.push({
          rule_id: 'wh-003',
          severity,
          issue: config?.thin_events
            ? `${vendor} uses thin events - payload is just notification, MUST fetch fresh data`
            : 'Webhook payload may be stale or incomplete - always fetch fresh data from API',
          remedy: 'On webhook receipt: 1) Validate signature, 2) Fetch fresh data from API, 3) Process based on fetched data',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'wh-004',
    name: 'No Idempotency/Deduplication',
    description: 'Must deduplicate webhook events (can arrive multiple times)',
    severity: 'HIGH',
    check: (code: string): WebhookViolation[] => {
      const violations: WebhookViolation[] = [];

      const hasWebhook = /webhook|event.*handler/i.test(code);
      const hasDedup = /idempoten|dedup|event[_-]?id|already.*processed|seen|unique/i.test(code);

      if (hasWebhook && !hasDedup) {
        violations.push({
          rule_id: 'wh-004',
          severity: 'HIGH',
          issue: 'No webhook deduplication - events can be delivered multiple times',
          remedy: 'Track processed events by event_id + timestamp + payload_hash (24-hour window)',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'wh-005',
    name: 'No Out-of-Order Handling',
    description: 'Webhook events can arrive out of order',
    severity: 'MEDIUM',
    check: (code: string): WebhookViolation[] => {
      const violations: WebhookViolation[] = [];

      const hasWebhook = /webhook|event.*handler/i.test(code);
      const hasOrderHandling = /timestamp|sequence|version|order|latest/i.test(code);

      if (hasWebhook && !hasOrderHandling) {
        violations.push({
          rule_id: 'wh-005',
          severity: 'MEDIUM',
          issue: 'Webhooks can arrive out of order - no handling detected',
          remedy: 'Compare event timestamp with current record timestamp, only process if newer',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'wh-006',
    name: 'Slack Timeout',
    description: 'Slack requires response within 3 seconds',
    severity: 'HIGH',
    check: (code: string, vendor?: string): WebhookViolation[] => {
      const violations: WebhookViolation[] = [];

      if (vendor !== 'slack') return violations;

      const hasAsyncProcessing = /async|queue|background|deferred|setTimeout|process\.nextTick/i.test(code);
      const hasImmediateResponse = /200.*immediate|respond.*quick|ack/i.test(code);

      if (!hasAsyncProcessing && !hasImmediateResponse) {
        violations.push({
          rule_id: 'wh-006',
          severity: 'HIGH',
          issue: 'Slack requires response within 3 seconds - async processing not detected',
          remedy: 'Acknowledge immediately (200 OK), process asynchronously in background',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'wh-007',
    name: 'No Retry Handling',
    description: 'Must handle webhook retry attempts from vendor',
    severity: 'MEDIUM',
    check: (code: string): WebhookViolation[] => {
      const violations: WebhookViolation[] = [];

      const hasWebhook = /webhook|event.*handler/i.test(code);
      const hasRetryHandling = /retry|attempt|x-.*-retry|delivery.*attempt/i.test(code);

      if (hasWebhook && !hasRetryHandling) {
        violations.push({
          rule_id: 'wh-007',
          severity: 'MEDIUM',
          issue: 'No handling for vendor retry attempts',
          remedy: 'Track delivery attempt count, implement idempotency to handle retried events',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'wh-008',
    name: 'No Webhook Timeout',
    description: 'Webhook processing must have timeout',
    severity: 'HIGH',
    check: (code: string): WebhookViolation[] => {
      const violations: WebhookViolation[] = [];

      const hasWebhook = /webhook|event.*handler/i.test(code);
      const hasTimeout = /timeout|abort|signal|deadline/i.test(code);

      if (hasWebhook && !hasTimeout) {
        violations.push({
          rule_id: 'wh-008',
          severity: 'HIGH',
          issue: 'No timeout for webhook processing - can hang indefinitely',
          remedy: 'Add 10-second timeout (3 seconds for Slack) to webhook handler',
          auto_fixable: true
        });
      }

      return violations;
    }
  },
  {
    id: 'wh-009',
    name: 'HubSpot Webhook Delays',
    description: 'HubSpot webhooks can be delayed up to 30 minutes',
    severity: 'MEDIUM',
    check: (code: string, vendor?: string): WebhookViolation[] => {
      const violations: WebhookViolation[] = [];

      if (vendor !== 'hubspot') return violations;

      const acknowledgesDelay = /delay|latency|eventual|30.*min|minutes/i.test(code);

      if (!acknowledgesDelay) {
        violations.push({
          rule_id: 'wh-009',
          severity: 'MEDIUM',
          issue: 'HubSpot webhooks can be delayed up to 30 minutes during peak',
          remedy: 'Do not rely on HubSpot webhooks for time-sensitive operations - use polling',
          auto_fixable: false
        });
      }

      return violations;
    }
  },
  {
    id: 'wh-010',
    name: 'No Dead Letter Queue for Webhooks',
    description: 'Failed webhook processing should go to DLQ',
    severity: 'MEDIUM',
    check: (code: string): WebhookViolation[] => {
      const violations: WebhookViolation[] = [];

      const hasWebhook = /webhook|event.*handler/i.test(code);
      const hasDLQ = /dead[_-]?letter|dlq|failed[_-]?queue/i.test(code);

      if (hasWebhook && !hasDLQ) {
        violations.push({
          rule_id: 'wh-010',
          severity: 'MEDIUM',
          issue: 'No DLQ for failed webhook processing',
          remedy: 'Store failed webhook events in DLQ for manual review and replay',
          auto_fixable: true
        });
      }

      return violations;
    }
  }
];

export function checkWebhookRules(code: string, vendor?: string): WebhookViolation[] {
  const violations: WebhookViolation[] = [];

  for (const rule of WEBHOOK_RULES) {
    violations.push(...rule.check(code, vendor));
  }

  return violations;
}

export function getVendorWebhookConfig(vendor: string): WebhookConfig | null {
  return VENDOR_WEBHOOK_CONFIGS[vendor.toLowerCase()] || null;
}
