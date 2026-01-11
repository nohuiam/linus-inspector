/**
 * Prompt Inspector
 *
 * Validates prompts for safety, clarity, token efficiency, and Anthropic guidelines.
 * Used for Pre-Build Mode inspections.
 */

import { generateId } from '../database/index.js';

export interface PromptInspectionOptions {
  prompt_id?: string;
  prompt_content: string;
  expected_output_format?: string;
  use_case?: string;
}

export interface PromptIssue {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  issue: string;
  location?: string;
  remedy: string;
}

export interface PromptInspectionResult {
  prompt_id: string;
  verdict: 'PASSED' | 'NEEDS_REVISION' | 'BLOCKED';
  safety_score: number;
  token_count: number;
  estimated_efficient_tokens: number;
  clarity_score: number;
  issues: PromptIssue[];
  anthropic_compliance: {
    passes: string[];
    fails: string[];
  };
}

/**
 * Estimate token count (rough approximation)
 */
function estimateTokens(text: string): number {
  // Rough approximation: ~4 characters per token for English
  return Math.ceil(text.length / 4);
}

/**
 * Check for prompt injection vectors
 */
function checkPromptInjection(prompt: string): PromptIssue[] {
  const issues: PromptIssue[] = [];

  // Check for direct instruction injection patterns
  const injectionPatterns = [
    { pattern: /ignore.*previous.*instructions/i, desc: 'Ignore previous instructions' },
    { pattern: /disregard.*above/i, desc: 'Disregard above' },
    { pattern: /forget.*everything/i, desc: 'Forget everything' },
    { pattern: /you\s+are\s+now/i, desc: 'Identity override attempt' },
    { pattern: /execute.*code/i, desc: 'Code execution request' },
    { pattern: /\$\{.*\}/, desc: 'Template literal interpolation' },
    { pattern: /\{\{.*\}\}/, desc: 'Mustache template interpolation' },
    { pattern: /<%.*%>/, desc: 'EJS template interpolation' }
  ];

  for (const { pattern, desc } of injectionPatterns) {
    if (pattern.test(prompt)) {
      issues.push({
        severity: 'CRITICAL',
        issue: `Potential prompt injection vector detected: ${desc}`,
        location: prompt.match(pattern)?.[0]?.substring(0, 50),
        remedy: 'Sanitize user input before interpolation, use allowlists for allowed values'
      });
    }
  }

  // Check for unsanitized variable interpolation
  if (/\$\{user_?input\}|\{\{user_?input\}\}/i.test(prompt)) {
    issues.push({
      severity: 'CRITICAL',
      issue: 'Direct user input interpolation without sanitization',
      remedy: 'Validate and sanitize user input before interpolating into prompts'
    });
  }

  return issues;
}

/**
 * Check for token efficiency
 */
function checkTokenEfficiency(prompt: string): PromptIssue[] {
  const issues: PromptIssue[] = [];
  const tokens = estimateTokens(prompt);

  // Check for repetition
  const sentences = prompt.split(/[.!?]+/).filter(s => s.trim().length > 20);
  const uniqueSentences = new Set(sentences.map(s => s.trim().toLowerCase()));

  if (sentences.length > uniqueSentences.size) {
    const duplicates = sentences.length - uniqueSentences.size;
    issues.push({
      severity: 'MEDIUM',
      issue: `Found ${duplicates} duplicate/similar sentences - wasting tokens`,
      remedy: 'Remove redundant sentences to reduce token usage'
    });
  }

  // Check for excessive examples
  const exampleMatches = prompt.match(/example|e\.g\.|for instance/gi) || [];
  if (exampleMatches.length > 5) {
    issues.push({
      severity: 'MEDIUM',
      issue: `${exampleMatches.length} examples detected - may be excessive`,
      remedy: 'Limit to 2-3 examples maximum, remove redundant ones'
    });
  }

  // Check for verbose phrasing
  const verbosePatterns = [
    /please\s+make\s+sure\s+to/i,
    /it\s+is\s+important\s+to\s+note\s+that/i,
    /in\s+order\s+to/i,
    /for\s+the\s+purpose\s+of/i,
    /at\s+this\s+point\s+in\s+time/i
  ];

  for (const pattern of verbosePatterns) {
    if (pattern.test(prompt)) {
      issues.push({
        severity: 'LOW',
        issue: 'Verbose phrasing detected - can be more concise',
        location: prompt.match(pattern)?.[0],
        remedy: 'Use direct language to reduce token usage'
      });
    }
  }

  return issues;
}

/**
 * Check for clarity
 */
function checkClarity(prompt: string): { score: number; issues: PromptIssue[] } {
  const issues: PromptIssue[] = [];
  let clarityDeductions = 0;

  // Check for ambiguous pronouns
  const pronounMatches = prompt.match(/\b(it|this|that|they|them)\b(?!\s+(is|are|was|were|will|can|should))/gi) || [];
  if (pronounMatches.length > 5) {
    clarityDeductions += 0.1;
    issues.push({
      severity: 'LOW',
      issue: 'Many ambiguous pronouns - may cause confusion',
      remedy: 'Replace ambiguous pronouns with specific nouns'
    });
  }

  // Check for contradictory instructions
  const contradictions = [
    { patterns: [/always/i, /never/i], desc: 'always/never' },
    { patterns: [/must/i, /optional/i], desc: 'must/optional' },
    { patterns: [/required/i, /if.*want/i], desc: 'required/optional' }
  ];

  for (const { patterns, desc } of contradictions) {
    if (patterns.every(p => p.test(prompt))) {
      clarityDeductions += 0.2;
      issues.push({
        severity: 'HIGH',
        issue: `Potentially contradictory instructions: ${desc}`,
        remedy: 'Review and reconcile conflicting directives'
      });
    }
  }

  // Check for missing output format
  if (!/format|output|return|respond|json|markdown|list/i.test(prompt)) {
    clarityDeductions += 0.15;
    issues.push({
      severity: 'MEDIUM',
      issue: 'No output format specified',
      remedy: 'Specify expected output format (JSON, markdown, list, etc.)'
    });
  }

  // Check for unclear scope
  if (!/only|specifically|limit|focus|do not/i.test(prompt) && prompt.length > 500) {
    clarityDeductions += 0.1;
    issues.push({
      severity: 'LOW',
      issue: 'Long prompt without explicit scope limitations',
      remedy: 'Add explicit boundaries for what the model should and should not do'
    });
  }

  const score = Math.max(0, 1 - clarityDeductions);
  return { score, issues };
}

/**
 * Check Anthropic guidelines compliance
 */
function checkAnthropicGuidelines(prompt: string): { passes: string[]; fails: string[] } {
  const passes: string[] = [];
  const fails: string[] = [];

  // Check for system prompt structure
  if (/^(you are|your role|as a)/i.test(prompt.trim())) {
    passes.push('role_definition');
  }

  // Check for clear task definition
  if (/task:|goal:|objective:|your job/i.test(prompt)) {
    passes.push('task_definition');
  } else if (prompt.length > 200) {
    fails.push('task_definition');
  }

  // Check for output expectations
  if (/respond|output|return|format|structure/i.test(prompt)) {
    passes.push('output_expectations');
  } else if (prompt.length > 300) {
    fails.push('output_expectations');
  }

  // Check for constraints
  if (/do not|don't|never|avoid|limit|only/i.test(prompt)) {
    passes.push('constraints_defined');
  }

  // Check for examples
  if (/example|e\.g\.|such as|like this/i.test(prompt)) {
    passes.push('examples_provided');
  }

  return { passes, fails };
}

/**
 * Calculate safety score
 */
function calculateSafetyScore(issues: PromptIssue[]): number {
  let score = 1.0;

  for (const issue of issues) {
    switch (issue.severity) {
      case 'CRITICAL':
        score -= 0.4;
        break;
      case 'HIGH':
        score -= 0.2;
        break;
      case 'MEDIUM':
        score -= 0.1;
        break;
      case 'LOW':
        score -= 0.05;
        break;
    }
  }

  return Math.max(0, score);
}

/**
 * Inspect a prompt
 */
export function inspectPrompt(options: PromptInspectionOptions): PromptInspectionResult {
  const promptId = options.prompt_id || generateId('prompt');
  const prompt = options.prompt_content;

  // Collect all issues
  const allIssues: PromptIssue[] = [];

  // Check for prompt injection
  allIssues.push(...checkPromptInjection(prompt));

  // Check token efficiency
  allIssues.push(...checkTokenEfficiency(prompt));

  // Check clarity
  const { score: clarityScore, issues: clarityIssues } = checkClarity(prompt);
  allIssues.push(...clarityIssues);

  // Check Anthropic guidelines
  const anthropicCompliance = checkAnthropicGuidelines(prompt);

  // Add issues for failed guidelines
  for (const fail of anthropicCompliance.fails) {
    allIssues.push({
      severity: 'MEDIUM',
      issue: `Anthropic guideline not met: ${fail.replace('_', ' ')}`,
      remedy: `Add ${fail.replace('_', ' ')} to improve prompt quality`
    });
  }

  // Calculate scores
  const tokenCount = estimateTokens(prompt);
  const estimatedEfficientTokens = Math.ceil(tokenCount * 0.7); // Assume 30% could be trimmed
  const safetyScore = calculateSafetyScore(allIssues);

  // Determine verdict
  let verdict: 'PASSED' | 'NEEDS_REVISION' | 'BLOCKED';
  const criticalCount = allIssues.filter(i => i.severity === 'CRITICAL').length;
  const highCount = allIssues.filter(i => i.severity === 'HIGH').length;

  if (criticalCount > 0) {
    verdict = 'BLOCKED';
  } else if (highCount > 0 || safetyScore < 0.7) {
    verdict = 'NEEDS_REVISION';
  } else {
    verdict = 'PASSED';
  }

  return {
    prompt_id: promptId,
    verdict,
    safety_score: safetyScore,
    token_count: tokenCount,
    estimated_efficient_tokens: estimatedEfficientTokens,
    clarity_score: clarityScore,
    issues: allIssues,
    anthropic_compliance: anthropicCompliance
  };
}
