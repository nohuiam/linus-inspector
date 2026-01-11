/**
 * Skill Validator
 *
 * Validates skill.md files against Anthropic's skill format guidelines.
 * Checks structure, description quality, trigger clarity, instructions, examples, safety.
 */

import { readFileSync } from 'fs';
import { generateId } from '../database/index.js';

export interface SkillValidationOptions {
  skill_path?: string;
  skill_content?: string;
  skill_name?: string;
}

export interface SkillIssue {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  section: string;
  issue: string;
  remedy: string;
}

export interface SkillValidationResult {
  skill_path: string;
  skill_name: string;
  verdict: 'PASSED' | 'NEEDS_REVISION' | 'BLOCKED';
  checks: {
    structure_valid: boolean;
    description_valid: boolean;
    triggers_valid: boolean;
    instructions_valid: boolean;
    examples_present: boolean;
    safety_valid: boolean;
  };
  issues: SkillIssue[];
  anthropic_compliance: {
    passes: string[];
    fails: string[];
  };
}

/**
 * Required sections for a valid skill
 */
const REQUIRED_SECTIONS = [
  'name',
  'description',
  'trigger',
  'instructions'
];

const OPTIONAL_SECTIONS = [
  'examples',
  'input',
  'output',
  'constraints',
  'dependencies'
];

/**
 * Parse skill markdown into sections
 */
function parseSkillMarkdown(content: string): Map<string, string> {
  const sections = new Map<string, string>();
  let currentSection = '';
  let currentContent: string[] = [];

  const lines = content.split('\n');

  for (const line of lines) {
    // Check for section header (## or #) - trim leading whitespace for robustness
    const trimmedLine = line.trim();
    const headerMatch = trimmedLine.match(/^#+\s*(.+)/);
    if (headerMatch) {
      // Save previous section
      if (currentSection) {
        sections.set(currentSection.toLowerCase(), currentContent.join('\n').trim());
      }
      // Normalize section name: lowercase, collapse non-alphanumeric to single underscore
      currentSection = headerMatch[1].toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
      currentContent = [];
    } else {
      currentContent.push(line);
    }
  }

  // Save last section
  if (currentSection) {
    sections.set(currentSection.toLowerCase(), currentContent.join('\n').trim());
  }

  return sections;
}

/**
 * Check skill structure
 */
function checkStructure(sections: Map<string, string>): { valid: boolean; issues: SkillIssue[] } {
  const issues: SkillIssue[] = [];
  let valid = true;

  // Check for required sections
  for (const section of REQUIRED_SECTIONS) {
    const found = Array.from(sections.keys()).some(key =>
      key.includes(section) || key === section
    );

    if (!found) {
      valid = false;
      issues.push({
        severity: 'CRITICAL',
        section: 'structure',
        issue: `Missing required section: ${section}`,
        remedy: `Add a ## ${section.charAt(0).toUpperCase() + section.slice(1)} section`
      });
    }
  }

  return { valid, issues };
}

/**
 * Check description quality
 */
function checkDescription(sections: Map<string, string>): { valid: boolean; issues: SkillIssue[] } {
  const issues: SkillIssue[] = [];
  let valid = true;

  const description = sections.get('description') || sections.get('skill_description') || '';

  if (!description) {
    valid = false;
    issues.push({
      severity: 'CRITICAL',
      section: 'description',
      issue: 'No description found',
      remedy: 'Add a clear, concise description of what the skill does'
    });
    return { valid, issues };
  }

  // Check length (should be concise, <200 chars for summary)
  if (description.length > 500) {
    issues.push({
      severity: 'LOW',
      section: 'description',
      issue: 'Description is very long - may be hard to scan',
      remedy: 'Keep main description under 200 characters, move details to instructions'
    });
  }

  // Check for actionable language
  if (!/\b(help|enable|allow|provide|generate|create|analyze|process)\b/i.test(description)) {
    issues.push({
      severity: 'MEDIUM',
      section: 'description',
      issue: 'Description lacks actionable verbs',
      remedy: 'Start description with what the skill does: "Helps users...", "Generates...", etc.'
    });
  }

  return { valid, issues };
}

/**
 * Check trigger clarity
 */
function checkTriggers(sections: Map<string, string>, allSectionContent: string): { valid: boolean; issues: SkillIssue[] } {
  const issues: SkillIssue[] = [];
  let valid = true;

  const triggers = sections.get('trigger') || sections.get('triggers') ||
                   sections.get('when_to_use') || sections.get('activation') || '';

  if (!triggers) {
    // Check if triggers are mentioned anywhere
    if (!/trigger|activate|invoke|when.*use|use.*when/i.test(allSectionContent)) {
      valid = false;
      issues.push({
        severity: 'HIGH',
        section: 'triggers',
        issue: 'No trigger conditions defined',
        remedy: 'Add a ## Trigger section explaining when this skill should be invoked'
      });
    }
    return { valid, issues };
  }

  // Check for ambiguous triggers
  const ambiguousPatterns = [
    /whenever|anytime|always/i,
    /might|maybe|possibly/i,
    /could.*or.*could/i
  ];

  for (const pattern of ambiguousPatterns) {
    if (pattern.test(triggers)) {
      issues.push({
        severity: 'MEDIUM',
        section: 'triggers',
        issue: 'Trigger conditions are ambiguous',
        remedy: 'Use specific, unambiguous trigger conditions'
      });
      break;
    }
  }

  // Check for overlapping trigger patterns (would need other skills to check)
  if (/data|sync|update/i.test(triggers) && triggers.split(/\s+/).length < 5) {
    issues.push({
      severity: 'LOW',
      section: 'triggers',
      issue: 'Generic trigger words may overlap with other skills',
      remedy: 'Be more specific: "sync hubspot contacts" instead of "sync data"'
    });
  }

  return { valid, issues };
}

/**
 * Check instructions quality
 */
function checkInstructions(sections: Map<string, string>): { valid: boolean; issues: SkillIssue[] } {
  const issues: SkillIssue[] = [];
  let valid = true;

  const instructions = sections.get('instructions') || sections.get('steps') ||
                       sections.get('procedure') || sections.get('how_to') || '';

  if (!instructions) {
    valid = false;
    issues.push({
      severity: 'CRITICAL',
      section: 'instructions',
      issue: 'No instructions found',
      remedy: 'Add step-by-step instructions for executing the skill'
    });
    return { valid, issues };
  }

  // Check for numbered steps
  const hasNumberedSteps = /^\s*\d+[.)]/m.test(instructions);
  const hasBulletSteps = /^\s*[-*•]/m.test(instructions);

  if (!hasNumberedSteps && !hasBulletSteps && instructions.length > 200) {
    issues.push({
      severity: 'MEDIUM',
      section: 'instructions',
      issue: 'Long instructions without clear step structure',
      remedy: 'Break instructions into numbered steps for clarity'
    });
  }

  // Check for ambiguous steps
  if (/then.*proceed|continue.*appropriate|as.*needed/i.test(instructions)) {
    issues.push({
      severity: 'HIGH',
      section: 'instructions',
      issue: 'Instructions contain ambiguous phrases',
      remedy: 'Make each step deterministic - Claude should know exactly what to do'
    });
  }

  // Check for safety considerations
  if (/delete|remove|modify|write|update/i.test(instructions)) {
    if (!/confirm|verify|check|backup|careful/i.test(instructions)) {
      issues.push({
        severity: 'HIGH',
        section: 'instructions',
        issue: 'Destructive operations without safety checks',
        remedy: 'Add confirmation or verification steps before destructive operations'
      });
    }
  }

  return { valid, issues };
}

/**
 * Check for examples
 */
function checkExamples(sections: Map<string, string>, allContent: string): { present: boolean; issues: SkillIssue[] } {
  const issues: SkillIssue[] = [];

  const examples = sections.get('examples') || sections.get('example') ||
                   sections.get('usage') || sections.get('sample') || '';

  // Also check for inline examples
  const hasInlineExamples = /example|e\.g\.|such as|like this|for instance/i.test(allContent);

  if (!examples && !hasInlineExamples) {
    issues.push({
      severity: 'MEDIUM',
      section: 'examples',
      issue: 'No examples provided',
      remedy: 'Add input/output examples demonstrating skill usage'
    });
    return { present: false, issues };
  }

  // Check example quality
  if (examples && examples.length < 50) {
    issues.push({
      severity: 'LOW',
      section: 'examples',
      issue: 'Examples section is brief',
      remedy: 'Provide more detailed examples with input and expected output'
    });
  }

  return { present: true, issues };
}

/**
 * Check for safety issues
 */
function checkSafety(content: string): { valid: boolean; issues: SkillIssue[] } {
  const issues: SkillIssue[] = [];
  let valid = true;

  // Check for dangerous operations
  const dangerousPatterns = [
    { pattern: /rm\s+-rf|delete.*all|drop\s+table/i, desc: 'Mass deletion command' },
    { pattern: /sudo|root|admin.*password/i, desc: 'Privilege escalation' },
    { pattern: /eval\s*\(|exec\s*\(/i, desc: 'Code execution' },
    { pattern: /api[_-]?key|secret|password/i, desc: 'Credential handling' },
    { pattern: /without.*confirmation|skip.*verification/i, desc: 'Bypassing safety checks' }
  ];

  for (const { pattern, desc } of dangerousPatterns) {
    if (pattern.test(content)) {
      if (desc === 'Credential handling') {
        issues.push({
          severity: 'MEDIUM',
          section: 'safety',
          issue: `Handles sensitive data: ${desc}`,
          remedy: 'Ensure credentials are handled via environment variables, never logged'
        });
      } else {
        valid = false;
        issues.push({
          severity: 'CRITICAL',
          section: 'safety',
          issue: `Potentially unsafe operation: ${desc}`,
          remedy: 'Add safety guards, confirmation steps, or remove dangerous operations'
        });
      }
    }
  }

  // Check for global state modification
  if (/global|singleton|shared.*state/i.test(content)) {
    issues.push({
      severity: 'HIGH',
      section: 'safety',
      issue: 'Skill may modify global state',
      remedy: 'Ensure skill is isolated and does not pollute global state'
    });
  }

  return { valid, issues };
}

/**
 * Check Anthropic compliance
 */
function checkAnthropicCompliance(sections: Map<string, string>, content: string): { passes: string[]; fails: string[] } {
  const passes: string[] = [];
  const fails: string[] = [];

  // Check structure
  if (sections.size >= 3) {
    passes.push('structure');
  } else {
    fails.push('structure');
  }

  // Check description
  if (sections.has('description') || sections.has('skill_description')) {
    passes.push('description');
  } else {
    fails.push('description');
  }

  // Check triggers
  if (sections.has('trigger') || sections.has('triggers') || /when.*use|trigger/i.test(content)) {
    passes.push('trigger_clarity');
  } else {
    fails.push('trigger_clarity');
  }

  // Check instructions
  if (sections.has('instructions') || sections.has('steps')) {
    passes.push('instructions');
  } else {
    fails.push('instructions');
  }

  // Check examples
  if (sections.has('examples') || sections.has('example') || /example/i.test(content)) {
    passes.push('examples');
  } else {
    fails.push('examples');
  }

  // Check safety
  if (/careful|verify|confirm|safe/i.test(content) || !/delete|remove|modify/i.test(content)) {
    passes.push('safety');
  } else {
    fails.push('safety');
  }

  return { passes, fails };
}

/**
 * Validate a skill
 */
export function validateSkill(options: SkillValidationOptions): SkillValidationResult {
  let content: string;
  const skillPath = options.skill_path || 'inline';

  if (options.skill_content) {
    content = options.skill_content;
  } else if (options.skill_path) {
    content = readFileSync(options.skill_path, 'utf-8');
  } else {
    throw new Error('Either skill_path or skill_content must be provided');
  }

  // Parse sections
  const sections = parseSkillMarkdown(content);

  // Detect skill name
  const skillName = options.skill_name ||
    sections.get('name') ||
    sections.get('skill_name') ||
    (options.skill_path ? options.skill_path.split('/').pop()?.replace('.md', '') : 'unknown') ||
    'unknown';

  // Run all checks
  const allIssues: SkillIssue[] = [];

  const structureCheck = checkStructure(sections);
  allIssues.push(...structureCheck.issues);

  const descriptionCheck = checkDescription(sections);
  allIssues.push(...descriptionCheck.issues);

  const triggersCheck = checkTriggers(sections, content);
  allIssues.push(...triggersCheck.issues);

  const instructionsCheck = checkInstructions(sections);
  allIssues.push(...instructionsCheck.issues);

  const examplesCheck = checkExamples(sections, content);
  allIssues.push(...examplesCheck.issues);

  const safetyCheck = checkSafety(content);
  allIssues.push(...safetyCheck.issues);

  const anthropicCompliance = checkAnthropicCompliance(sections, content);

  // Add issues for failed compliance
  for (const fail of anthropicCompliance.fails) {
    if (!allIssues.some(i => i.section === fail || i.issue.toLowerCase().includes(fail))) {
      allIssues.push({
        severity: 'MEDIUM',
        section: fail,
        issue: `Anthropic guideline not met: ${fail.replace('_', ' ')}`,
        remedy: `Review and improve ${fail.replace('_', ' ')}`
      });
    }
  }

  // Determine verdict
  let verdict: 'PASSED' | 'NEEDS_REVISION' | 'BLOCKED';
  const criticalCount = allIssues.filter(i => i.severity === 'CRITICAL').length;
  const highCount = allIssues.filter(i => i.severity === 'HIGH').length;

  if (criticalCount > 0) {
    verdict = 'BLOCKED';
  } else if (highCount > 0 || anthropicCompliance.fails.length > 2) {
    verdict = 'NEEDS_REVISION';
  } else {
    verdict = 'PASSED';
  }

  return {
    skill_path: skillPath,
    skill_name: skillName,
    verdict,
    checks: {
      structure_valid: structureCheck.valid,
      description_valid: descriptionCheck.valid,
      triggers_valid: triggersCheck.valid,
      instructions_valid: instructionsCheck.valid,
      examples_present: examplesCheck.present,
      safety_valid: safetyCheck.valid
    },
    issues: allIssues,
    anthropic_compliance: anthropicCompliance
  };
}
