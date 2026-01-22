/**
 * Self-Inspection Tool
 *
 * "Physician, heal thyself"
 *
 * This tool allows linus-inspector to inspect its own codebase,
 * running all standard rules plus meta-rules specific to inspectors.
 */

import { z } from 'zod';
import { readFileSync, readdirSync, statSync, existsSync } from 'fs';
import { join, dirname, resolve } from 'path';
import { fileURLToPath } from 'url';
import { runProfileAwareInspections, type ProfileAwareInspectionResult } from '../rules/index.js';
import { checkMetaRules, type MetaViolation, type MetaInspectionContext } from '../rules/meta-rules.js';
import { createInspection, createInspectionIssue, generateId } from '../database/index.js';
import { detectServerProfile } from '../profiler/profile-detector.js';
import type { ServerProfile, ServerType } from '../profiler/server-profile.js';

// ============================================================================
// Schema
// ============================================================================

export const InspectSelfSchema = z.object({
  include_meta_rules: z.boolean()
    .optional()
    .default(true)
    .describe('Include meta-rules specific to inspectors (physician heal thyself checks)'),
  emit_signal: z.boolean()
    .optional()
    .default(false)
    .describe('Emit InterLock signal on completion'),
  verbose: z.boolean()
    .optional()
    .default(false)
    .describe('Include detailed file-by-file results')
});

export type InspectSelfParams = z.infer<typeof InspectSelfSchema>;

// ============================================================================
// Types
// ============================================================================

export interface SelfInspectionResult {
  inspection_id: string;
  server_name: string;
  server_path: string;
  verdict: 'PASSED' | 'WARNING' | 'BLOCKED';
  summary: {
    total_files: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    meta_violations: number;
    auto_fixable: number;
  };
  issues: Array<{
    severity: string;
    category: string;
    file: string;
    issue: string;
    remedy: string;
    auto_fixable: boolean;
  }>;
  meta_issues: MetaViolation[];
  duration_ms: number;
  physician_healed: boolean;  // true if no critical/high meta-violations
  // Profile-aware inspection info
  profile?: {
    type: ServerType;
    hasExternalAPIs: boolean;
    hasOAuth: boolean;
    hasWebhooks: boolean;
    hasDatabaseWrites: boolean;
    isMCPServer: boolean;
  };
  skipped_categories?: Array<{ category: string; reason: string }>;
  applied_categories?: string[];
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get the root path of linus-inspector
 */
function getSelfPath(): string {
  // In ESM, we need to derive __dirname
  const currentFile = fileURLToPath(import.meta.url);
  const currentDir = dirname(currentFile);

  // Go up from src/tools to project root
  return resolve(currentDir, '..', '..');
}

/**
 * Get all TypeScript/JavaScript source files
 */
function getSourceFiles(rootPath: string): string[] {
  const files: string[] = [];
  const srcPath = join(rootPath, 'src');

  if (!existsSync(srcPath)) {
    return files;
  }

  function walkDir(dir: string): void {
    const entries = readdirSync(dir);

    for (const entry of entries) {
      const fullPath = join(dir, entry);
      const stat = statSync(fullPath);

      if (stat.isDirectory()) {
        // Skip node_modules, dist, tests
        if (!['node_modules', 'dist', 'tests', '.git'].includes(entry)) {
          walkDir(fullPath);
        }
      } else if (stat.isFile()) {
        // Include .ts and .js files
        if (/\.(ts|js)$/.test(entry) && !entry.endsWith('.d.ts')) {
          files.push(fullPath);
        }
      }
    }
  }

  walkDir(srcPath);
  return files;
}

/**
 * Determine inspection categories based on codebase
 */
function detectInspectionCategories(files: string[]): string[] {
  const categories: Set<string> = new Set();

  for (const file of files) {
    const content = readFileSync(file, 'utf-8');

    if (/rate[_-]?limit/i.test(content)) categories.add('rate_limiting');
    if (/oauth|auth|token/i.test(content)) categories.add('oauth');
    if (/error[_-]?handling|catch\s*\(/i.test(content)) categories.add('error_handling');
    if (/webhook/i.test(content)) categories.add('webhooks');
    if (/compliance|hipaa|gdpr|soc2|pci/i.test(content)) categories.add('compliance');
    if (/data[_-]?integrity|idempotency/i.test(content)) categories.add('data_integrity');
    if (/security|credential|secret/i.test(content)) categories.add('security');
    if (/test|coverage|jest|vitest/i.test(content)) categories.add('test_coverage');
  }

  return [...categories];
}

// ============================================================================
// Main Handler
// ============================================================================

/**
 * Inspect linus-inspector's own codebase
 */
export async function inspectSelf(params: InspectSelfParams): Promise<SelfInspectionResult> {
  const startTime = Date.now();
  const selfPath = getSelfPath();

  // Get source files
  const files = getSourceFiles(selfPath);

  // Detect own profile for context-aware rule filtering
  const profile = await detectServerProfile(selfPath);

  if (files.length === 0) {
    return {
      inspection_id: generateId('self-insp'),  // Not stored in DB, just for response
      server_name: 'linus-inspector',
      server_path: selfPath,
      verdict: 'BLOCKED',
      summary: {
        total_files: 0,
        critical: 1,
        high: 0,
        medium: 0,
        low: 0,
        meta_violations: 0,
        auto_fixable: 0
      },
      issues: [{
        severity: 'CRITICAL',
        category: 'structure',
        file: selfPath,
        issue: 'No source files found for self-inspection',
        remedy: 'Ensure src/ directory exists with TypeScript files',
        auto_fixable: false
      }],
      meta_issues: [],
      duration_ms: Date.now() - startTime,
      physician_healed: false
    };
  }

  // Collect all issues
  const allIssues: SelfInspectionResult['issues'] = [];
  const allMetaIssues: MetaViolation[] = [];

  // Track profile-aware filtering results (same for all files)
  let skippedCategories: Array<{ category: string; reason: string }> = [];
  let appliedCategories: string[] = [];

  // Determine what this inspector checks
  const inspectionCategories = detectInspectionCategories(files);

  // Build meta-inspection context
  const metaContext: MetaInspectionContext = {
    is_inspector: true,
    server_type: 'inspector',
    inspection_categories: inspectionCategories
  };

  // Inspect each file with profile-aware rule filtering
  for (const file of files) {
    try {
      const code = readFileSync(file, 'utf-8');
      const relativePath = file.replace(selfPath + '/', '');

      // Run profile-aware inspection rules (skips inapplicable categories)
      const result = runProfileAwareInspections(code, profile, {});

      // Capture skipped/applied categories from first file (same for all)
      if (skippedCategories.length === 0 && result.skipped_categories) {
        skippedCategories = result.skipped_categories;
        appliedCategories = result.applied_categories;
      }

      // Collect issues from all categories
      for (const categoryResult of result.results) {
        for (const violation of categoryResult.violations) {
          allIssues.push({
            severity: violation.severity,
            category: categoryResult.category,
            file: relativePath,
            issue: violation.issue,
            remedy: violation.remedy,
            auto_fixable: violation.auto_fixable || false
          });
        }
      }

      // Run meta-rules if enabled (these should always run for inspectors)
      if (params.include_meta_rules) {
        const metaViolations = checkMetaRules(code, metaContext);
        for (const violation of metaViolations) {
          // Add file context to meta violations
          allMetaIssues.push({
            ...violation,
            issue: `[${relativePath}] ${violation.issue}`
          });
        }
      }
    } catch (error: any) {
      allIssues.push({
        severity: 'HIGH',
        category: 'self_inspection',
        file: file,
        issue: `Failed to inspect file: ${error.message}`,
        remedy: 'Check file permissions and syntax',
        auto_fixable: false
      });
    }
  }

  // Calculate summary
  const summary = {
    total_files: files.length,
    critical: allIssues.filter(i => i.severity === 'CRITICAL').length +
              allMetaIssues.filter(i => i.severity === 'CRITICAL').length,
    high: allIssues.filter(i => i.severity === 'HIGH').length +
          allMetaIssues.filter(i => i.severity === 'HIGH').length,
    medium: allIssues.filter(i => i.severity === 'MEDIUM').length +
            allMetaIssues.filter(i => i.severity === 'MEDIUM').length,
    low: allIssues.filter(i => i.severity === 'LOW').length +
         allMetaIssues.filter(i => i.severity === 'LOW').length,
    meta_violations: allMetaIssues.length,
    auto_fixable: allIssues.filter(i => i.auto_fixable).length +
                  allMetaIssues.filter(i => i.auto_fixable).length
  };

  // Determine verdict
  let verdict: 'PASSED' | 'WARNING' | 'BLOCKED';
  if (summary.critical > 0) {
    verdict = 'BLOCKED';
  } else if (summary.high > 0) {
    verdict = 'WARNING';
  } else {
    verdict = 'PASSED';
  }

  // Check if physician has healed thyself (no critical/high meta-violations)
  const criticalMetaIssues = allMetaIssues.filter(
    i => i.severity === 'CRITICAL' || i.severity === 'HIGH'
  );
  const physicianHealed = criticalMetaIssues.length === 0;

  const duration = Date.now() - startTime;

  // Store in database
  let storedInspectionId = generateId('self-insp'); // Fallback if DB fails
  try {
    // Capture returned inspection to get the actual DB-generated ID
    const inspection = createInspection({
      build_id: `self-${Date.now()}`,
      server_name: 'linus-inspector',
      server_type: 'inspector',
      mode: 'build',  // Use 'build' mode for self-inspection
      verdict,
      summary_critical: summary.critical,
      summary_high: summary.high,
      summary_medium: summary.medium,
      summary_low: summary.low,
      duration_ms: duration,
      auto_fixes_available: summary.auto_fixable,
      auto_fixes_applied: 0
    });
    storedInspectionId = inspection.id;

    // Store issues using the actual inspection ID from the database
    for (const issue of allIssues.slice(0, 100)) { // Limit to 100
      createInspectionIssue({
        inspection_id: inspection.id,
        severity: issue.severity as any,
        category: issue.category,
        location: issue.file,
        issue: issue.issue,
        remedy: issue.remedy,
        auto_fixable: issue.auto_fixable,
        auto_fixed: false
      });
    }

    // Store meta-issues as a special category
    for (const issue of allMetaIssues) {
      createInspectionIssue({
        inspection_id: inspection.id,
        severity: issue.severity,
        category: 'meta_inspection',
        location: 'self',
        issue: issue.issue,
        remedy: issue.remedy,
        auto_fixable: issue.auto_fixable,
        auto_fixed: false
      });
    }
  } catch (error) {
    // Database storage failure is not critical
    console.error('Failed to store self-inspection results:', error);
  }

  return {
    inspection_id: storedInspectionId,
    server_name: 'linus-inspector',
    server_path: selfPath,
    verdict,
    summary,
    issues: allIssues,
    meta_issues: allMetaIssues,
    duration_ms: duration,
    physician_healed: physicianHealed,
    // Profile-aware inspection info
    profile: {
      type: profile.type,
      hasExternalAPIs: profile.hasExternalAPIs,
      hasOAuth: profile.hasOAuth,
      hasWebhooks: profile.hasWebhooks,
      hasDatabaseWrites: profile.hasDatabaseWrites,
      isMCPServer: profile.isMCPServer
    },
    skipped_categories: skippedCategories,
    applied_categories: appliedCategories
  };
}

// ============================================================================
// Tool Definition (for export to tools/index.ts)
// ============================================================================

export const inspectSelfTool = {
  description: 'Run all inspections on linus-inspector itself (physician heal thyself). Includes meta-rules that detect ironic gaps like a rate-limit inspector without rate limiting.',
  schema: InspectSelfSchema,
  handler: inspectSelf
};
