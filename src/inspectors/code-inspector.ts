/**
 * Code Quality Inspector
 *
 * Runs all code-level inspections using research-backed rules.
 * Used for Build Mode inspections.
 */

import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { glob } from 'glob';
import {
  runAllInspections,
  type FullInspectionResult,
  type AnyViolation,
  SUPPORTED_VENDORS,
  SUPPORTED_REGULATIONS
} from '../rules/index.js';
import {
  createInspection,
  createInspectionIssue,
  updateInspectionVerdict,
  generateId
} from '../database/index.js';

export interface CodeInspectionOptions {
  server_path: string;
  server_name?: string;
  server_type?: string;
  vendor?: string;
  regulation?: string;
  industry?: string;
  build_id?: string;
}

export interface CodeInspectionResult {
  inspection_id: string;
  build_id: string;
  server_name: string;
  verdict: 'PASSED' | 'BLOCKED' | 'WARNING';
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total_files: number;
    total_violations: number;
    auto_fixable: number;
  };
  issues: Array<{
    severity: string;
    category: string;
    file: string;
    location?: string;
    issue: string;
    remedy: string;
    auto_fixable: boolean;
  }>;
  duration_ms: number;
}

/**
 * Detect vendor from code/config
 */
function detectVendor(code: string, configContent?: string): string | undefined {
  const allContent = code + (configContent || '');

  for (const vendor of SUPPORTED_VENDORS) {
    const pattern = new RegExp(vendor, 'i');
    if (pattern.test(allContent)) {
      return vendor;
    }
  }

  // Check for API URLs
  const vendorUrls: Record<string, RegExp> = {
    salesforce: /force\.com|salesforce\.com/i,
    hubspot: /hubapi\.com|hubspot\.com/i,
    stripe: /stripe\.com/i,
    snowflake: /snowflakecomputing\.com/i,
    zendesk: /zendesk\.com/i,
    slack: /slack\.com/i,
    quickbooks: /intuit\.com|quickbooks/i,
    shopify: /shopify\.com|myshopify/i,
    servicenow: /service-now\.com|servicenow/i,
    microsoft365: /graph\.microsoft\.com|office365/i
  };

  for (const [vendor, pattern] of Object.entries(vendorUrls)) {
    if (pattern.test(allContent)) {
      return vendor;
    }
  }

  return undefined;
}

/**
 * Detect compliance regulation from code/config
 */
function detectRegulation(code: string, configContent?: string): string | undefined {
  const allContent = code + (configContent || '');

  for (const regulation of SUPPORTED_REGULATIONS) {
    const pattern = new RegExp(regulation.replace('-', '[_-]?'), 'i');
    if (pattern.test(allContent)) {
      return regulation;
    }
  }

  // Check for regulation-related keywords
  const regulationKeywords: Record<string, RegExp> = {
    HIPAA: /phi|patient|medical|healthcare|health.*data/i,
    GDPR: /gdpr|eu.*data|personal.*data|data.*subject/i,
    'PCI-DSS': /card.*number|payment.*card|cvv|pan|pci/i,
    SOC2: /soc.*2|audit.*trail|access.*review/i
  };

  for (const [regulation, pattern] of Object.entries(regulationKeywords)) {
    if (pattern.test(allContent)) {
      return regulation;
    }
  }

  return undefined;
}

/**
 * Get all code files from a directory
 */
async function getCodeFiles(serverPath: string): Promise<string[]> {
  const patterns = [
    '**/*.ts',
    '**/*.js',
    '**/*.tsx',
    '**/*.jsx'
  ];

  const files: string[] = [];

  for (const pattern of patterns) {
    const matches = await glob(pattern, {
      cwd: serverPath,
      ignore: ['**/node_modules/**', '**/dist/**', '**/build/**', '**/*.test.*', '**/*.spec.*']
    });
    files.push(...matches.map(f => join(serverPath, f)));
  }

  return files;
}

/**
 * Inspect a single code file
 */
function inspectFile(
  filePath: string,
  vendor?: string,
  regulation?: string
): { violations: AnyViolation[]; category_results: Map<string, AnyViolation[]> } {
  let code: string;
  try {
    code = readFileSync(filePath, 'utf-8');
  } catch (error) {
    return { violations: [], category_results: new Map() };
  }

  const result = runAllInspections(code, { vendor, regulation });

  const categoryResults = new Map<string, AnyViolation[]>();
  for (const categoryResult of result.results) {
    categoryResults.set(categoryResult.category, categoryResult.violations);
  }

  return {
    violations: result.results.flatMap(r => r.violations),
    category_results: categoryResults
  };
}

/**
 * Main code inspection function
 */
export async function inspectCode(options: CodeInspectionOptions): Promise<CodeInspectionResult> {
  const startTime = Date.now();
  const buildId = options.build_id || generateId('build');

  // Get server name from path if not provided
  const serverName = options.server_name || options.server_path.split('/').pop() || 'unknown';

  // Try to read config file for auto-detection
  let configContent: string | undefined;
  try {
    const configPath = join(options.server_path, 'config', 'interlock.json');
    configContent = readFileSync(configPath, 'utf-8');
  } catch {
    // Config file not found, that's ok
  }

  // Read a sample of code files for auto-detection
  const codeFiles = await getCodeFiles(options.server_path);
  let sampleCode = '';
  for (const file of codeFiles.slice(0, 5)) {
    try {
      sampleCode += readFileSync(file, 'utf-8') + '\n';
    } catch {
      // File read failed, skip
    }
  }

  // Auto-detect vendor and regulation if not provided
  const vendor = options.vendor || detectVendor(sampleCode, configContent);
  const regulation = options.regulation || detectRegulation(sampleCode, configContent);

  // Create inspection record
  const inspection = createInspection({
    build_id: buildId,
    server_name: serverName,
    server_type: options.server_type,
    industry: options.industry,
    mode: 'build',
    verdict: 'PASSED', // Will be updated
    summary_critical: 0,
    summary_high: 0,
    summary_medium: 0,
    summary_low: 0,
    auto_fixes_available: 0,
    auto_fixes_applied: 0
  });

  // Collect all violations
  const allIssues: CodeInspectionResult['issues'] = [];
  let totalCritical = 0;
  let totalHigh = 0;
  let totalMedium = 0;
  let totalLow = 0;
  let totalAutoFixable = 0;

  // Inspect each file
  for (const filePath of codeFiles) {
    const relativePath = filePath.replace(options.server_path, '').replace(/^\//, '');
    const { violations } = inspectFile(filePath, vendor, regulation);

    for (const violation of violations) {
      // Create issue record
      createInspectionIssue({
        inspection_id: inspection.id,
        severity: violation.severity,
        category: 'rule_id' in violation ? violation.rule_id.split('-')[0] : 'unknown',
        location: `${relativePath}${violation.location ? ':' + violation.location : ''}`,
        issue: violation.issue,
        remedy: violation.remedy,
        auto_fixable: violation.auto_fixable,
        auto_fixed: false
      });

      allIssues.push({
        severity: violation.severity,
        category: 'rule_id' in violation ? violation.rule_id.split('-')[0] : 'unknown',
        file: relativePath,
        location: violation.location,
        issue: violation.issue,
        remedy: violation.remedy,
        auto_fixable: violation.auto_fixable
      });

      // Count by severity
      switch (violation.severity) {
        case 'CRITICAL':
          totalCritical++;
          break;
        case 'HIGH':
          totalHigh++;
          break;
        case 'MEDIUM':
          totalMedium++;
          break;
        case 'LOW':
          totalLow++;
          break;
      }

      if (violation.auto_fixable) {
        totalAutoFixable++;
      }
    }
  }

  const durationMs = Date.now() - startTime;

  // Determine verdict
  let verdict: 'PASSED' | 'BLOCKED' | 'WARNING';
  if (totalCritical > 0 || totalHigh > 0) {
    verdict = 'BLOCKED';
  } else if (totalMedium > 0) {
    verdict = 'WARNING';
  } else {
    verdict = 'PASSED';
  }

  // Update inspection record
  updateInspectionVerdict(inspection.id, verdict, {
    critical: totalCritical,
    high: totalHigh,
    medium: totalMedium,
    low: totalLow,
    auto_fixes_available: totalAutoFixable,
    auto_fixes_applied: 0,
    duration_ms: durationMs
  });

  return {
    inspection_id: inspection.id,
    build_id: buildId,
    server_name: serverName,
    verdict,
    summary: {
      critical: totalCritical,
      high: totalHigh,
      medium: totalMedium,
      low: totalLow,
      total_files: codeFiles.length,
      total_violations: allIssues.length,
      auto_fixable: totalAutoFixable
    },
    issues: allIssues,
    duration_ms: durationMs
  };
}

/**
 * Quick inspection of a single file or code string
 */
export function quickInspect(
  codeOrPath: string,
  options: { vendor?: string; regulation?: string; is_path?: boolean } = {}
): FullInspectionResult {
  let code: string;

  if (options.is_path) {
    code = readFileSync(codeOrPath, 'utf-8');
  } else {
    code = codeOrPath;
  }

  return runAllInspections(code, {
    vendor: options.vendor,
    regulation: options.regulation
  });
}
