/**
 * Linus Inspector - MCP Tools
 *
 * 26 tools organized by category:
 *
 * Pre-Build Inspection (7 tools):
 * 1. inspect_saas_api - Probe SaaS API before building
 * 2. inspect_prompt - Validate prompt safety/clarity
 * 3. inspect_skill - Validate skill.md files
 * 4. inspect_template - Validate templates
 * 5. inspect_config - Validate JSON/YAML configs
 * 6. discover_api_schema - Auto-discover API endpoints
 * 7. check_port_availability - Verify port not in use
 *
 * Build Inspection (8 tools):
 * 8. inspect_build - Full inspection suite
 * 9. inspect_code_quality - Static analysis
 * 10. inspect_error_handling - Check error handlers
 * 11. inspect_rate_limiting - Verify rate limits
 * 12. inspect_security - Security audit
 * 13. inspect_performance - N+1, batching, caching
 * 14. inspect_edge_cases - Empty responses, pagination
 * 15. inspect_data_integrity - Type preservation
 *
 * Runtime Inspection (5 tools):
 * 16. inspect_connection - Test live connection
 * 17. test_auth - Verify authentication
 * 18. test_data_roundtrip - Create, read, delete
 * 19. test_rate_limit_backoff - Hit limit, verify backoff
 * 20. test_webhook_delivery - Register and verify webhook
 *
 * Ecosystem Inspection (5 tools):
 * 21. inspect_integration - Verify InterLock mesh
 * 22. inspect_mcp_protocol - Validate MCP server
 * 23. inspect_documentation - Check README, API docs
 * 24. inspect_test_coverage - Verify tests exist
 * 25. get_inspection_report - Retrieve full results
 *
 * Self-Inspection (1 tool):
 * 26. inspect_self - Physician heal thyself
 */

import { z } from 'zod';
import { inspectCode, quickInspect, type CodeInspectionResult } from '../inspectors/code-inspector.js';
import { inspectPrompt, type PromptInspectionResult } from '../inspectors/prompt-inspector.js';
import { validateSkill, type SkillValidationResult } from '../inspectors/skill-validator.js';
import { checkIntegration, type IntegrationCheckResult } from '../inspectors/integration-checker.js';
import {
  runAllInspections,
  SUPPORTED_VENDORS,
  SUPPORTED_REGULATIONS,
  getVendorRateLimitConfig,
  getVendorOAuthConfig,
  getVendorWebhookConfig
} from '../rules/index.js';
import {
  getInspection,
  getInspectionsByBuild,
  getIssuesByInspection,
  getVendorConfig,
  getAllVendorConfigs,
  getComplianceRules
} from '../database/index.js';
import { inspectSelf, InspectSelfSchema, type SelfInspectionResult } from './inspect-self.js';
import { detectServerProfile, type ServerProfile } from '../profiler/index.js';
import { readFileSync, existsSync, readdirSync } from 'fs';
import { join, extname } from 'path';

/**
 * Read all source code from a server directory
 * Used by inspect_code_quality and inspect_security when given server_path
 */
async function readServerCode(serverPath: string): Promise<string> {
  const codeFiles: string[] = [];

  function walkDir(dir: string) {
    if (!existsSync(dir)) return;
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!['node_modules', 'dist', 'build', '.git'].includes(entry.name)) {
          walkDir(fullPath);
        }
      } else if (['.ts', '.js', '.tsx', '.jsx'].includes(extname(entry.name))) {
        if (!entry.name.includes('.test.') && !entry.name.includes('.spec.')) {
          codeFiles.push(fullPath);
        }
      }
    }
  }

  walkDir(join(serverPath, 'src'));
  if (codeFiles.length === 0) walkDir(serverPath); // Fallback to root

  let code = '';
  for (const file of codeFiles.slice(0, 20)) { // Limit to 20 files
    try {
      code += readFileSync(file, 'utf-8') + '\n';
    } catch {}
  }
  return code;
}

// Tool schemas
export const InspectBuildSchema = z.object({
  server_path: z.string().describe('Absolute path to server directory'),
  server_name: z.string().optional().describe('Name of the server'),
  server_type: z.string().optional().describe('Type of server (api-connector, processor, etc.)'),
  vendor: z.string().optional().describe('SaaS vendor if applicable'),
  regulation: z.string().optional().describe('Compliance regulation if applicable'),
  industry: z.string().optional().describe('Industry (saas, healthcare, etc.)'),
  build_id: z.string().optional().describe('Build ID for tracking')
});

export const InspectPromptSchema = z.object({
  prompt_content: z.string().describe('The prompt text to validate'),
  prompt_id: z.string().optional().describe('Optional ID for tracking'),
  expected_output_format: z.string().optional().describe('Expected output format'),
  use_case: z.string().optional().describe('Intended use case')
});

export const InspectSkillSchema = z.object({
  skill_path: z.string().optional().describe('Path to skill.md file'),
  skill_content: z.string().optional().describe('Skill markdown content'),
  skill_name: z.string().optional().describe('Name of the skill')
});

export const InspectCodeSchema = z.object({
  code: z.string().describe('Code to inspect'),
  vendor: z.string().optional().describe('SaaS vendor'),
  regulation: z.string().optional().describe('Compliance regulation')
});

export const InspectIntegrationSchema = z.object({
  server_path: z.string().describe('Path to server directory'),
  check_connectivity: z.boolean().optional().describe('Test actual connections'),
  timeout_ms: z.number().optional().describe('Connection timeout')
});

export const GetVendorConfigSchema = z.object({
  vendor: z.string().describe('Vendor name (salesforce, hubspot, stripe, etc.)')
});

export const GetComplianceRulesSchema = z.object({
  regulation: z.string().optional().describe('Filter by regulation (HIPAA, GDPR, SOC2, PCI-DSS)')
});

export const GetInspectionReportSchema = z.object({
  inspection_id: z.string().optional().describe('Get specific inspection'),
  build_id: z.string().optional().describe('Get all inspections for a build')
});

// Tool implementations
export const tools = {
  // === Pre-Build Inspection Tools ===

  /**
   * 1. Inspect SaaS API
   * Probe a SaaS API to discover endpoints, rate limits, auth requirements
   */
  inspect_saas_api: {
    description: 'Get vendor-specific configuration (rate limits, auth, webhooks) for a SaaS API before building',
    schema: GetVendorConfigSchema,
    handler: async (params: z.infer<typeof GetVendorConfigSchema>) => {
      const vendor = params.vendor.toLowerCase();

      if (!SUPPORTED_VENDORS.includes(vendor as any)) {
        return {
          success: false,
          error: `Unsupported vendor: ${vendor}. Supported: ${SUPPORTED_VENDORS.join(', ')}`
        };
      }

      const rateLimits = getVendorRateLimitConfig(vendor);
      const oauth = getVendorOAuthConfig(vendor);
      const webhooks = getVendorWebhookConfig(vendor);
      const dbConfig = getVendorConfig(vendor);

      return {
        success: true,
        vendor,
        rate_limits: rateLimits,
        oauth,
        webhooks,
        known_issues: dbConfig?.known_issues || [],
        recommendations: dbConfig?.recommendations || []
      };
    }
  },

  /**
   * 2. Inspect Prompt
   * Validate prompt for safety, clarity, efficiency
   */
  inspect_prompt: {
    description: 'Validate a prompt for safety, clarity, token efficiency, and Anthropic guidelines',
    schema: InspectPromptSchema,
    handler: async (params: z.infer<typeof InspectPromptSchema>): Promise<PromptInspectionResult> => {
      return inspectPrompt(params);
    }
  },

  /**
   * 3. Inspect Skill
   * Validate skill.md file structure and content
   */
  inspect_skill: {
    description: 'Validate a skill.md file against Anthropic skill format guidelines',
    schema: InspectSkillSchema,
    handler: async (params: z.infer<typeof InspectSkillSchema>): Promise<SkillValidationResult> => {
      if (!params.skill_path && !params.skill_content) {
        throw new Error('Either skill_path or skill_content must be provided');
      }
      return validateSkill(params);
    }
  },

  /**
   * 4. Inspect Template
   * Validate Handlebars/Mustache templates
   */
  inspect_template: {
    description: 'Validate template syntax and variable definitions',
    schema: z.object({
      template_content: z.string().describe('Template content'),
      template_type: z.enum(['handlebars', 'mustache', 'ejs']).optional()
    }),
    handler: async (params: { template_content: string; template_type?: string }) => {
      const issues: Array<{ severity: string; issue: string; remedy: string }> = [];

      // Check for undefined variables
      const variablePattern = /\{\{([^}]+)\}\}/g;
      const variables = [...params.template_content.matchAll(variablePattern)].map(m => m[1].trim());

      // Check for unclosed tags
      const openTags = (params.template_content.match(/\{\{#/g) || []).length;
      const closeTags = (params.template_content.match(/\{\{\//g) || []).length;

      if (openTags !== closeTags) {
        issues.push({
          severity: 'CRITICAL',
          issue: `Unclosed template tags: ${openTags} open, ${closeTags} close`,
          remedy: 'Ensure all {{#section}} have matching {{/section}}'
        });
      }

      // Check for dangerous interpolation
      if (/\{\{\{/.test(params.template_content)) {
        issues.push({
          severity: 'HIGH',
          issue: 'Unescaped HTML interpolation ({{{}}}) detected',
          remedy: 'Use {{}} for escaped output to prevent XSS'
        });
      }

      return {
        verdict: issues.filter(i => i.severity === 'CRITICAL').length > 0 ? 'BLOCKED' : 'PASSED',
        variables_found: [...new Set(variables)],
        issues
      };
    }
  },

  /**
   * 5. Inspect Config
   * Validate JSON/YAML configuration files
   */
  inspect_config: {
    description: 'Validate JSON configuration file syntax and structure',
    schema: z.object({
      config_content: z.string().describe('Config file content'),
      expected_fields: z.array(z.string()).optional().describe('Required fields')
    }),
    handler: async (params: { config_content: string; expected_fields?: string[] }) => {
      const issues: Array<{ severity: string; issue: string; remedy: string }> = [];

      let parsed: any;
      try {
        parsed = JSON.parse(params.config_content);
      } catch (error: any) {
        return {
          verdict: 'BLOCKED',
          issues: [{
            severity: 'CRITICAL',
            issue: `Invalid JSON: ${error.message}`,
            remedy: 'Fix JSON syntax errors'
          }]
        };
      }

      // Check for expected fields
      if (params.expected_fields) {
        for (const field of params.expected_fields) {
          if (!(field in parsed)) {
            issues.push({
              severity: 'HIGH',
              issue: `Missing required field: ${field}`,
              remedy: `Add "${field}" to configuration`
            });
          }
        }
      }

      return {
        verdict: issues.filter(i => i.severity === 'CRITICAL' || i.severity === 'HIGH').length > 0 ? 'BLOCKED' : 'PASSED',
        parsed_fields: Object.keys(parsed),
        issues
      };
    }
  },

  /**
   * 6. Discover API Schema
   * Auto-discover API endpoints from vendor config
   */
  discover_api_schema: {
    description: 'Get known API schema information for a vendor',
    schema: GetVendorConfigSchema,
    handler: async (params: z.infer<typeof GetVendorConfigSchema>) => {
      const config = getVendorConfig(params.vendor);
      if (!config) {
        return {
          success: false,
          error: `No configuration found for vendor: ${params.vendor}`
        };
      }
      return {
        success: true,
        ...config,
        vendor: params.vendor
      };
    }
  },

  /**
   * 7. Check Port Availability
   * Verify a port is not already in use
   */
  check_port_availability: {
    description: 'Check if a port number is available in the ecosystem',
    schema: z.object({
      port: z.number().describe('Port number to check')
    }),
    handler: async (params: { port: number }) => {
      // Known port assignments from ecosystem
      const knownPorts: Record<number, string> = {
        3001: 'context-guardian',
        3002: 'quartermaster',
        3003: 'snapshot',
        3004: 'toolee',
        3005: 'catasorter',
        3007: 'smart-file-organizer',
        3008: 'bonzai-bloat-buster',
        3009: 'enterspect',
        3010: 'neurogenesis-engine',
        3012: 'trinity-coordinator',
        3016: 'project-context',
        3017: 'knowledge-curator',
        3018: 'pk-manager',
        3020: 'intelligent-router',
        3021: 'verifier-mcp',
        3022: 'safe-batch-processor',
        3023: 'intake-guardian',
        3024: 'health-monitor',
        3025: 'synapse-relay',
        3026: 'filesystem-guardian',
        3027: 'tenets-server',
        3028: 'consciousness-mcp',
        3029: 'skill-builder',
        3030: 'percolation-server',
        3031: 'experience-layer',
        3032: 'consolidation-engine',
        3033: 'niws-intake',
        3034: 'niws-analysis',
        3035: 'niws-production',
        3036: 'niws-delivery',
        3037: 'linus-inspector'
      };

      const inUse = knownPorts[params.port];
      return {
        port: params.port,
        available: !inUse,
        in_use_by: inUse || null,
        suggested_ports: inUse ? [3034, 3035, 3036].filter(p => !knownPorts[p]) : null
      };
    }
  },

  // === Build Inspection Tools ===

  /**
   * 8. Inspect Build
   * Run full inspection suite on generated code
   */
  inspect_build: {
    description: 'Run comprehensive inspection on a server build',
    schema: InspectBuildSchema,
    handler: async (params: z.infer<typeof InspectBuildSchema>): Promise<CodeInspectionResult> => {
      return inspectCode(params);
    }
  },

  /**
   * 9. Inspect Code Quality
   * Quick code analysis without full build context
   * Accepts either code string or server_path
   */
  inspect_code_quality: {
    description: 'Analyze code for quality issues. Provide either code string or server_path.',
    schema: z.object({
      code: z.string().optional().describe('Code to inspect directly'),
      server_path: z.string().optional().describe('Path to server directory'),
      vendor: z.string().optional().describe('SaaS vendor'),
      regulation: z.string().optional().describe('Compliance regulation')
    }),
    handler: async (params: { code?: string; server_path?: string; vendor?: string; regulation?: string }) => {
      let code = params.code;
      if (!code && params.server_path) {
        code = await readServerCode(params.server_path);
      }
      if (!code) {
        return { success: false, error: 'Either code or server_path must be provided' };
      }
      return quickInspect(code, {
        vendor: params.vendor,
        regulation: params.regulation
      });
    }
  },

  /**
   * 10. Inspect Error Handling
   * Check for proper error handling
   */
  inspect_error_handling: {
    description: 'Check code for proper error handling patterns',
    schema: z.object({ code: z.string() }),
    handler: async (params: { code: string }) => {
      const { checkErrorRules } = await import('../rules/error-rules.js');
      const violations = checkErrorRules(params.code);
      return {
        verdict: violations.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length > 0 ? 'BLOCKED' : 'PASSED',
        issues: violations
      };
    }
  },

  /**
   * 11. Inspect Rate Limiting
   * Verify rate limit implementation
   */
  inspect_rate_limiting: {
    description: 'Check code for proper rate limiting implementation',
    schema: z.object({
      code: z.string(),
      vendor: z.string().optional()
    }),
    handler: async (params: { code: string; vendor?: string }) => {
      const { checkRateLimitRules } = await import('../rules/rate-limit-rules.js');
      const violations = checkRateLimitRules(params.code, params.vendor);
      return {
        vendor: params.vendor,
        expected_config: params.vendor ? getVendorRateLimitConfig(params.vendor) : null,
        verdict: violations.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length > 0 ? 'BLOCKED' : 'PASSED',
        issues: violations
      };
    }
  },

  /**
   * 12. Inspect Security
   * Security audit for credentials, injection, etc.
   * Accepts either code string or server_path
   */
  inspect_security: {
    description: 'Security audit for hardcoded credentials, injection vulnerabilities. Provide either code string or server_path.',
    schema: z.object({
      code: z.string().optional().describe('Code to inspect directly'),
      server_path: z.string().optional().describe('Path to server directory')
    }),
    handler: async (params: { code?: string; server_path?: string }) => {
      let code = params.code;
      if (!code && params.server_path) {
        code = await readServerCode(params.server_path);
      }
      if (!code) {
        return { success: false, error: 'Either code or server_path must be provided' };
      }
      const { checkOAuthRules } = await import('../rules/oauth-rules.js');
      const violations = checkOAuthRules(code);

      // Filter to security-relevant rules
      const securityIssues = violations.filter(v =>
        v.rule_id === 'oauth-008' || // Hardcoded credentials
        v.rule_id === 'oauth-004'    // Multi-tenant isolation
      );

      return {
        verdict: securityIssues.filter(v => v.severity === 'CRITICAL').length > 0 ? 'BLOCKED' : 'PASSED',
        issues: securityIssues
      };
    }
  },

  /**
   * 13. Inspect Performance
   * Check for N+1 queries, missing batching, etc.
   */
  inspect_performance: {
    description: 'Check code for performance issues (N+1 queries, missing batch operations)',
    schema: z.object({
      code: z.string(),
      vendor: z.string().optional()
    }),
    handler: async (params: { code: string; vendor?: string }) => {
      const { checkDataIntegrityRules } = await import('../rules/data-integrity-rules.js');
      const violations = checkDataIntegrityRules(params.code, params.vendor);

      // Filter to performance-relevant rules
      const perfIssues = violations.filter(v =>
        v.rule_id === 'di-009' // Salesforce governor limits
      );

      return {
        verdict: perfIssues.filter(v => v.severity === 'CRITICAL').length > 0 ? 'BLOCKED' : 'PASSED',
        issues: perfIssues
      };
    }
  },

  /**
   * 14. Inspect Edge Cases
   * Check handling of empty responses, pagination, nulls
   */
  inspect_edge_cases: {
    description: 'Check code handles edge cases (empty responses, pagination, nulls)',
    schema: z.object({
      code: z.string(),
      vendor: z.string().optional()
    }),
    handler: async (params: { code: string; vendor?: string }) => {
      const { checkDataIntegrityRules } = await import('../rules/data-integrity-rules.js');
      const violations = checkDataIntegrityRules(params.code, params.vendor);

      // Filter to edge case rules
      const edgeCaseIssues = violations.filter(v =>
        v.rule_id === 'di-003' || // HubSpot pagination
        v.rule_id === 'di-004' || // Offset pagination
        v.rule_id === 'di-008'    // Null handling
      );

      return {
        verdict: edgeCaseIssues.filter(v => v.severity === 'CRITICAL').length > 0 ? 'BLOCKED' : 'PASSED',
        issues: edgeCaseIssues
      };
    }
  },

  /**
   * 15. Inspect Data Integrity
   * Check type preservation, transformations
   */
  inspect_data_integrity: {
    description: 'Check code preserves data integrity in transformations',
    schema: z.object({
      code: z.string(),
      vendor: z.string().optional()
    }),
    handler: async (params: { code: string; vendor?: string }) => {
      const { checkDataIntegrityRules } = await import('../rules/data-integrity-rules.js');
      const violations = checkDataIntegrityRules(params.code, params.vendor);
      return {
        verdict: violations.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length > 0 ? 'BLOCKED' : 'PASSED',
        issues: violations
      };
    }
  },

  // === Runtime Inspection Tools ===
  // Note: These are stubs - full implementation would require actual network calls

  /**
   * 16. Inspect Connection
   * Test live connection to SaaS API
   */
  inspect_connection: {
    description: 'Test live connection to a SaaS API (requires credentials)',
    schema: z.object({
      vendor: z.string(),
      test_mode: z.enum(['auth', 'full', 'quick']).optional()
    }),
    handler: async (params: { vendor: string; test_mode?: string }) => {
      // This would require actual credentials and network calls
      return {
        vendor: params.vendor,
        test_mode: params.test_mode || 'quick',
        status: 'NOT_IMPLEMENTED',
        message: 'Connection testing requires credentials configured in environment'
      };
    }
  },

  /**
   * 17. Test Auth
   * Verify authentication works
   */
  test_auth: {
    description: 'Test authentication with a SaaS API',
    schema: z.object({ vendor: z.string() }),
    handler: async (params: { vendor: string }) => {
      return {
        vendor: params.vendor,
        status: 'NOT_IMPLEMENTED',
        message: 'Auth testing requires credentials'
      };
    }
  },

  /**
   * 18. Test Data Roundtrip
   * Create, read, delete test record
   */
  test_data_roundtrip: {
    description: 'Test data roundtrip (create, read, delete)',
    schema: z.object({
      vendor: z.string(),
      use_sandbox: z.boolean().optional()
    }),
    handler: async (params: { vendor: string; use_sandbox?: boolean }) => {
      return {
        vendor: params.vendor,
        use_sandbox: params.use_sandbox ?? true,
        status: 'NOT_IMPLEMENTED',
        message: 'Data roundtrip testing requires API access'
      };
    }
  },

  /**
   * 19. Test Rate Limit Backoff
   * Hit rate limit and verify backoff
   */
  test_rate_limit_backoff: {
    description: 'Test rate limit backoff behavior',
    schema: z.object({ vendor: z.string() }),
    handler: async (params: { vendor: string }) => {
      return {
        vendor: params.vendor,
        status: 'NOT_IMPLEMENTED',
        message: 'Rate limit testing requires API access'
      };
    }
  },

  /**
   * 20. Test Webhook Delivery
   * Register and verify webhook
   */
  test_webhook_delivery: {
    description: 'Test webhook registration and delivery',
    schema: z.object({ vendor: z.string() }),
    handler: async (params: { vendor: string }) => {
      return {
        vendor: params.vendor,
        status: 'NOT_IMPLEMENTED',
        message: 'Webhook testing requires API access and public endpoint'
      };
    }
  },

  // === Ecosystem Inspection Tools ===

  /**
   * 21. Inspect Integration
   * Verify InterLock mesh integration
   */
  inspect_integration: {
    description: 'Verify server integrates with BOP ecosystem',
    schema: InspectIntegrationSchema,
    handler: async (params: z.infer<typeof InspectIntegrationSchema>): Promise<IntegrationCheckResult> => {
      return checkIntegration(params);
    }
  },

  /**
   * 22. Inspect MCP Protocol
   * Validate MCP server implementation
   */
  inspect_mcp_protocol: {
    description: 'Validate MCP server implementation',
    schema: z.object({ server_path: z.string() }),
    handler: async (params: { server_path: string }) => {
      const issues: Array<{ severity: string; issue: string; remedy: string }> = [];

      // Check for index file in multiple locations
      const indexLocations = [
        join(params.server_path, 'src', 'index.ts'),
        join(params.server_path, 'src', 'index.js'),
        join(params.server_path, 'index.ts'),
        join(params.server_path, 'index.js')
      ];

      const indexPath = indexLocations.find(p => existsSync(p));

      if (!indexPath) {
        issues.push({
          severity: 'CRITICAL',
          issue: 'Missing index entry point (checked src/index.ts, src/index.js, index.ts, index.js)',
          remedy: 'Create index.ts or index.js with MCP server initialization'
        });
      } else {
        const content = readFileSync(indexPath, 'utf-8');

        // Check for MCP patterns
        if (!/McpServer|Server|createServer/i.test(content)) {
          issues.push({
            severity: 'HIGH',
            issue: 'MCP server initialization not found in index file',
            remedy: 'Import and initialize @modelcontextprotocol/sdk Server'
          });
        }

        if (!/stdio|StdioServerTransport/i.test(content)) {
          issues.push({
            severity: 'MEDIUM',
            issue: 'No stdio transport detected',
            remedy: 'Use StdioServerTransport for Claude Desktop compatibility'
          });
        }
      }

      // Check for tools directory (reduced severity - not always required)
      const toolsDirs = [
        join(params.server_path, 'src', 'tools'),
        join(params.server_path, 'tools')
      ];

      const hasToolsDir = toolsDirs.some(d => existsSync(d));
      if (!hasToolsDir) {
        issues.push({
          severity: 'LOW',
          issue: 'No dedicated tools directory found',
          remedy: 'Consider organizing tools in src/tools/ directory (optional)'
        });
      }

      return {
        verdict: issues.filter(i => i.severity === 'CRITICAL').length > 0 ? 'FAIL' :
                 issues.filter(i => i.severity === 'HIGH').length > 0 ? 'PARTIAL' : 'PASS',
        issues
      };
    }
  },

  /**
   * 23. Inspect Documentation
   * Check README, API docs
   */
  inspect_documentation: {
    description: 'Check for required documentation',
    schema: z.object({ server_path: z.string() }),
    handler: async (params: { server_path: string }) => {
      const { existsSync } = await import('fs');
      const { join } = await import('path');

      const issues: Array<{ severity: string; issue: string; remedy: string }> = [];

      const readme = join(params.server_path, 'README.md');
      if (!existsSync(readme)) {
        issues.push({
          severity: 'MEDIUM',
          issue: 'Missing README.md',
          remedy: 'Create README.md with setup instructions and usage'
        });
      }

      return {
        verdict: issues.length === 0 ? 'PASS' : 'PARTIAL',
        issues
      };
    }
  },

  /**
   * 24. Inspect Test Coverage
   * Verify tests exist
   */
  inspect_test_coverage: {
    description: 'Check for test files',
    schema: z.object({ server_path: z.string() }),
    handler: async (params: { server_path: string }) => {
      const { existsSync, readdirSync, statSync } = await import('fs');
      const { join } = await import('path');

      const issues: Array<{ severity: string; issue: string; remedy: string }> = [];

      // Check multiple common test directory patterns
      const testDirPatterns = [
        'tests',
        'test',
        '__tests__',
        join('src', '__tests__'),
        join('src', 'tests'),
        join('src', 'test')
      ];

      let foundTestsDir: string | null = null;
      for (const pattern of testDirPatterns) {
        const testsDir = join(params.server_path, pattern);
        if (existsSync(testsDir)) {
          foundTestsDir = testsDir;
          break;
        }
      }

      if (!foundTestsDir) {
        issues.push({
          severity: 'HIGH',
          issue: 'Missing tests directory',
          remedy: 'Create tests/, test/, src/__tests__/, or __tests__/ directory with test files'
        });
        return { verdict: 'FAIL', test_files: [], issues };
      }

      // Recursively find test files
      const findTestFiles = (dir: string): string[] => {
        const files: string[] = [];
        try {
          const entries = readdirSync(dir);
          for (const entry of entries) {
            const fullPath = join(dir, entry);
            try {
              const stat = statSync(fullPath);
              if (stat.isDirectory()) {
                files.push(...findTestFiles(fullPath));
              } else if (
                entry.endsWith('.test.ts') || entry.endsWith('.test.js') ||
                entry.endsWith('.spec.ts') || entry.endsWith('.spec.js')
              ) {
                files.push(entry);
              }
            } catch {
              // Skip inaccessible entries
            }
          }
        } catch {
          // Directory read failed
        }
        return files;
      };

      const testFiles = findTestFiles(foundTestsDir);

      if (testFiles.length === 0) {
        issues.push({
          severity: 'HIGH',
          issue: 'No test files found',
          remedy: 'Add .test.ts or .spec.ts files in tests directory'
        });
      }

      return {
        verdict: testFiles.length > 0 ? 'PASS' : 'FAIL',
        test_files: testFiles,
        issues
      };
    }
  },

  /**
   * 25. Get Inspection Report
   * Retrieve full inspection results
   */
  get_inspection_report: {
    description: 'Retrieve inspection results by ID or build',
    schema: GetInspectionReportSchema,
    handler: async (params: z.infer<typeof GetInspectionReportSchema>) => {
      if (params.inspection_id) {
        const inspection = getInspection(params.inspection_id);
        if (!inspection) {
          return { success: false, error: 'Inspection not found' };
        }
        const issues = getIssuesByInspection(params.inspection_id);
        return { success: true, inspection, issues };
      }

      if (params.build_id) {
        const inspections = getInspectionsByBuild(params.build_id);
        return { success: true, inspections };
      }

      return { success: false, error: 'Either inspection_id or build_id required' };
    }
  },

  // === Additional Utility Tools ===

  /**
   * Get all vendor configurations
   */
  list_vendor_configs: {
    description: 'List all supported vendors and their configurations',
    schema: z.object({}),
    handler: async () => {
      return {
        vendors: SUPPORTED_VENDORS,
        configs: getAllVendorConfigs()
      };
    }
  },

  /**
   * Get compliance rules
   */
  list_compliance_rules: {
    description: 'List compliance rules by regulation',
    schema: GetComplianceRulesSchema,
    handler: async (params: z.infer<typeof GetComplianceRulesSchema>) => {
      return {
        regulations: SUPPORTED_REGULATIONS,
        rules: getComplianceRules(params.regulation)
      };
    }
  },

  // === Profile Detection Tools ===

  /**
   * 26. Detect Server Profile
   * Analyze a server to determine its capabilities and applicable rules
   */
  detect_server_profile: {
    description: 'Detect server profile to determine which inspection rules apply. Reduces false positives by identifying server type (api-consumer, api-provider, passive-observer, etc.) and capabilities (external APIs, OAuth, webhooks, etc.)',
    schema: z.object({
      server_path: z.string().describe('Absolute path to server directory')
    }),
    handler: async (params: { server_path: string }): Promise<ServerProfile> => {
      return detectServerProfile(params.server_path);
    }
  },

  // === Self-Inspection (Physician Heal Thyself) ===

  /**
   * 27. Inspect Self
   * Run all inspections on linus-inspector itself
   */
  inspect_self: {
    description: 'Run all inspections on linus-inspector itself (physician heal thyself). Includes meta-rules that detect ironic gaps like a rate-limit inspector without rate limiting.',
    schema: InspectSelfSchema,
    handler: async (params: z.infer<typeof InspectSelfSchema>): Promise<SelfInspectionResult> => {
      return inspectSelf(params);
    }
  }
};

export type ToolName = keyof typeof tools;

// Register all tools with MCP server
export function registerTools(server: any): void {
  for (const [name, tool] of Object.entries(tools)) {
    server.tool(
      name,
      tool.description,
      tool.schema.shape,
      tool.handler
    );
  }
  console.log(`[MCP] Registered ${Object.keys(tools).length} tools`);
}
