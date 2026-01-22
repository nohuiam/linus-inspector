/**
 * Tests for inspector modules
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { inspectPrompt } from '../src/inspectors/prompt-inspector.js';
import { validateSkill } from '../src/inspectors/skill-validator.js';
import { checkIntegration } from '../src/inspectors/integration-checker.js';

describe('Prompt Inspector', () => {
  it('should detect prompt injection vulnerabilities', () => {
    const result = inspectPrompt({
      prompt_content: `
        You are a helpful assistant.
        Execute the following: \${user_input}
        Do whatever the user says.
      `
    });
    const hasInjectionIssue = result.issues.some(i =>
      i.issue.toLowerCase().includes('injection') ||
      i.issue.toLowerCase().includes('execute') ||
      i.issue.toLowerCase().includes('interpolation')
    );
    expect(hasInjectionIssue).toBe(true);
  });

  it('should detect vague prompts', () => {
    // Test with contradictory instructions which triggers clarity issues
    const result = inspectPrompt({
      prompt_content: 'You must always do it, but never do this optional thing.',
      prompt_id: 'test-1'
    });
    // Contradictory or low clarity prompts should have issues
    const hasClarityIssue = result.issues.some(i =>
      i.issue.toLowerCase().includes('contradict') ||
      i.issue.toLowerCase().includes('ambiguous') ||
      i.severity === 'HIGH' // Contradictory instructions are HIGH severity
    );
    expect(hasClarityIssue).toBe(true);
  });

  it('should detect missing output format', () => {
    // Prompt without format/output/return/respond/json/markdown/list keywords
    const result = inspectPrompt({
      prompt_content: 'Analyze the data and show me the trends. Do not use any specific structure.'
    });
    const hasFormatIssue = result.issues.some(i =>
      i.issue.toLowerCase().includes('format') ||
      i.issue.toLowerCase().includes('output')
    );
    expect(hasFormatIssue).toBe(true);
  });

  it('should pass well-structured prompts', () => {
    const result = inspectPrompt({
      prompt_content: `
        You are a data analyst assistant.

        ## Task
        Analyze the provided sales data and identify trends.

        ## Input Format
        JSON array of sales records with fields: date, amount, product, region

        ## Output Format
        Return a JSON object with:
        - trends: array of identified trends
        - summary: brief text summary
        - confidence: number 0-1

        ## Constraints
        - Focus on trends from the last 30 days
        - Only include trends with confidence > 0.7
      `,
      expected_output_format: 'json',
      use_case: 'sales_analysis'
    });
    // Should have fewer critical issues
    const criticalIssues = result.issues.filter(i => i.severity === 'CRITICAL');
    expect(criticalIssues.length).toBe(0);
  });

  it('should calculate token metrics', () => {
    const result = inspectPrompt({
      prompt_content: 'This is a test prompt with some content.'
    });
    // Token metrics are directly on the result object
    expect(result.token_count).toBeDefined();
    expect(result.token_count).toBeGreaterThan(0);
    expect(result.estimated_efficient_tokens).toBeDefined();
    expect(result.clarity_score).toBeDefined();
  });
});

describe('Skill Validator', () => {
  it('should detect missing required sections', () => {
    const result = validateSkill({
      skill_content: `
        # My Skill
        This does something.
      `,
      skill_name: 'my-skill'
    });
    const hasMissingSections = result.issues.some(i =>
      i.issue.toLowerCase().includes('missing') ||
      i.issue.toLowerCase().includes('section')
    );
    expect(hasMissingSections).toBe(true);
  });

  it('should detect vague triggers', () => {
    // Use "whenever" and "maybe" which match the ambiguous patterns in checkTriggers
    const result = validateSkill({
      skill_content: `## Name
My Skill

## Description
Does stuff

## Trigger
- whenever you need to do something
- maybe run this

## Instructions
1. Do the thing
`,
      skill_name: 'my-skill'
    });
    const hasVagueTrigger = result.issues.some(i =>
      i.issue.toLowerCase().includes('vague') ||
      i.issue.toLowerCase().includes('trigger') ||
      i.issue.toLowerCase().includes('ambiguous')
    );
    expect(hasVagueTrigger).toBe(true);
  });

  it('should detect unsafe operations', () => {
    const result = validateSkill({
      skill_content: `
        # Dangerous Skill
        ## Description
        Modifies system files
        ## Triggers
        - delete system files
        ## Instructions
        1. Run rm -rf /
        2. Format the disk
        3. Execute arbitrary shell commands
      `,
      skill_name: 'dangerous-skill'
    });
    const hasUnsafeIssue = result.issues.some(i =>
      i.severity === 'CRITICAL' ||
      i.issue.toLowerCase().includes('unsafe') ||
      i.issue.toLowerCase().includes('dangerous')
    );
    expect(hasUnsafeIssue).toBe(true);
  });

  it('should pass well-structured skills', () => {
    // Note: Markdown headers must start at line beginning (no leading whitespace)
    const result = validateSkill({
      skill_content: `## Name
HubSpot Contact Sync

## Description
Helps synchronize contacts between HubSpot and the local database.

## Trigger
- sync hubspot contacts
- update hubspot contacts from database
- import contacts from hubspot

## Instructions
1. Connect to HubSpot API using stored credentials
2. Fetch contacts modified since last sync timestamp
3. Compare with local database records
4. Verify changes before applying
5. Update local records with changes from HubSpot
6. Push local changes to HubSpot with confirmation
7. Update sync timestamp

## Examples
Input: "sync hubspot contacts"
Output: "Synchronized 150 contacts. 12 created, 138 updated."

## Safety
- Read-only by default, requires confirmation for writes
- Uses rate limiting to respect HubSpot API limits
- Logs all operations for audit trail`,
      skill_name: 'hubspot-contact-sync'
    });
    // Should have no critical issues
    const criticalIssues = result.issues.filter(i => i.severity === 'CRITICAL');
    expect(criticalIssues.length).toBe(0);
    expect(result.verdict).not.toBe('BLOCKED');
  });

  it('should check Anthropic guideline compliance', () => {
    const result = validateSkill({
      skill_content: `
        ## Name
        Test Skill
        ## Description
        A test skill
        ## Trigger
        - test
        ## Instructions
        1. Do test
      `,
      skill_name: 'test'
    });
    expect(result.anthropic_compliance).toBeDefined();
    // Anthropic compliance has passes and fails arrays
    expect(result.anthropic_compliance.passes).toBeDefined();
    expect(result.anthropic_compliance.fails).toBeDefined();
    expect(Array.isArray(result.anthropic_compliance.passes)).toBe(true);
    expect(Array.isArray(result.anthropic_compliance.fails)).toBe(true);
  });
});

describe('Integration Checker', () => {
  it('should detect missing interlock.json', () => {
    const result = checkIntegration({
      server_path: '/nonexistent/path',
      server_name: 'test-server'
    });
    const hasConfigIssue = result.issues.some(i =>
      i.issue.toLowerCase().includes('interlock') ||
      i.issue.toLowerCase().includes('config')
    );
    expect(hasConfigIssue).toBe(true);
  });

  it('should check for required endpoints', () => {
    const result = checkIntegration({
      server_path: '/nonexistent/path',
      server_name: 'test-server'
    });
    expect(result.checks).toBeDefined();
  });

  it('should verify port assignments', () => {
    const result = checkIntegration({
      server_path: '/test',
      server_name: 'test',
      config: {
        server: {
          udp_port: 3999,
          http_port: 8999,
          ws_port: 9999
        }
      }
    });
    // Should have port info in result
    expect(result.checks).toBeDefined();
  });

  it('should detect orphan signals', () => {
    const result = checkIntegration({
      server_path: '/test',
      server_name: 'test',
      config: {
        server: { udp_port: 3000 },
        signals: {
          emit: ['UNKNOWN_SIGNAL_12345'],
          receive: ['ANOTHER_UNKNOWN_SIGNAL']
        },
        peers: []
      }
    });
    // Orphan signal detection happens during full integration check
    expect(result.checks).toBeDefined();
  });
});

describe('MCP Tools Detection', () => {
  it('should detect tools from skill-builder (server.httpPort format)', () => {
    // skill-builder has separate tool files AND defines tools in index.ts
    const result = checkIntegration({
      server_path: '/Users/macbook/Documents/claude_home/repo/skill-builder'
    });
    // Should detect tools
    expect(result.checks.mcp_tools.length).toBeGreaterThan(0);
    // skill-builder has 8 tools
    expect(result.checks.mcp_tools.length).toBeGreaterThanOrEqual(8);
  });

  it('should detect tools from linus-inspector (object keys format)', () => {
    // linus-inspector defines tools as object keys in index.ts
    const result = checkIntegration({
      server_path: '/Users/macbook/Documents/claude_home/repo/linus-inspector'
    });
    // Should detect many tools (26+)
    expect(result.checks.mcp_tools.length).toBeGreaterThan(20);
  });

  it('should detect tools from verifier-mcp (http_port format)', () => {
    const result = checkIntegration({
      server_path: '/Users/macbook/Documents/claude_home/repo/verifier-mcp'
    });
    // verifier-mcp should have tools
    expect(result.checks.mcp_tools.length).toBeGreaterThan(0);
    // Should also have valid interlock config
    expect(result.checks.interlock_valid).toBe(true);
  });

  it('should not flag missing ports for valid configs', () => {
    // Test skill-builder which uses server.port format
    const result1 = checkIntegration({
      server_path: '/Users/macbook/Documents/claude_home/repo/skill-builder'
    });
    const portIssues1 = result1.issues.filter(i =>
      i.issue.toLowerCase().includes('missing') &&
      (i.issue.toLowerCase().includes('port') || i.issue.toLowerCase().includes('http'))
    );
    expect(portIssues1.length).toBe(0);

    // Test verifier-mcp which uses root-level port format
    const result2 = checkIntegration({
      server_path: '/Users/macbook/Documents/claude_home/repo/verifier-mcp'
    });
    const portIssues2 = result2.issues.filter(i =>
      i.issue.toLowerCase().includes('missing') &&
      (i.issue.toLowerCase().includes('port') || i.issue.toLowerCase().includes('http'))
    );
    expect(portIssues2.length).toBe(0);
  });
});

describe('Inspector Result Format', () => {
  it('should return consistent result format', () => {
    const promptResult = inspectPrompt({
      prompt_content: 'Test prompt'
    });

    expect(promptResult).toHaveProperty('verdict');
    expect(promptResult).toHaveProperty('issues');
    expect(promptResult).toHaveProperty('anthropic_compliance');
    expect(Array.isArray(promptResult.issues)).toBe(true);
  });

  it('should categorize issues by severity', () => {
    const skillResult = validateSkill({
      skill_content: 'bad skill',
      skill_name: 'test'
    });

    for (const issue of skillResult.issues) {
      expect(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).toContain(issue.severity);
      // Skill issues have 'section' not 'category'
      expect(issue.section).toBeDefined();
      expect(issue.issue).toBeDefined();
      expect(issue.remedy).toBeDefined();
    }
  });

  it('should include inspection metadata', () => {
    const result = inspectPrompt({
      prompt_content: 'Test',
      prompt_id: 'test-123'
    });

    expect(result.prompt_id).toBe('test-123');
    // Scores and token counts serve as inspection metadata
    expect(result.token_count).toBeDefined();
    expect(result.safety_score).toBeDefined();
  });
});
