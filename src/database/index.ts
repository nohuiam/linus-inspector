import Database from 'better-sqlite3';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let db: Database.Database | null = null;

export function getDatabase(): Database.Database {
  if (!db) {
    const dbPath = join(__dirname, '../../data/linus-inspector.db');
    db = new Database(dbPath);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    initializeSchema();
  }
  return db;
}

function initializeSchema(): void {
  if (!db) return;

  // Check if database already has tables
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='inspections'").get();
  if (tables) {
    // Database already initialized
    return;
  }

  const schemaPath = join(__dirname, 'schema.sql');
  const schema = readFileSync(schemaPath, 'utf-8');
  db.exec(schema);
}

export function closeDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

// Alias for compatibility
export const initDatabase = getDatabase;
export const getDb = getDatabase;

// Save inspection (simplified interface for tests)
export function saveInspection(data: {
  id: string;
  build_id: string;
  server_name: string;
  server_path?: string;
  verdict: string;
  summary_critical: number;
  summary_high: number;
  summary_medium: number;
  summary_low: number;
}): void {
  const database = getDatabase();
  database.prepare(`
    INSERT OR REPLACE INTO inspections (id, build_id, server_name, server_type, mode, verdict,
      summary_critical, summary_high, summary_medium, summary_low,
      auto_fixes_available, auto_fixes_applied, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
  `).run(
    data.id, data.build_id, data.server_name, null, 'build', data.verdict,
    data.summary_critical, data.summary_high, data.summary_medium, data.summary_low,
    0, 0
  );
}

// Save issue (simplified interface for tests)
export function saveIssue(data: {
  id: string;
  inspection_id: string;
  severity: string;
  category: string;
  location?: string;
  issue: string;
  remedy?: string;
  auto_fixable?: boolean;
}): void {
  const database = getDatabase();
  database.prepare(`
    INSERT OR REPLACE INTO inspection_issues (id, inspection_id, severity, category, location, issue, remedy, auto_fixable, auto_fixed, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
  `).run(
    data.id, data.inspection_id, data.severity, data.category,
    data.location || null, data.issue, data.remedy || null,
    data.auto_fixable ? 1 : 0, 0
  );
}

// Helper functions for common operations

export function generateId(prefix: string): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `${prefix}-${timestamp}-${random}`;
}

export interface InspectionRecord {
  id: string;
  build_id: string;
  server_name: string;
  server_type?: string;
  industry?: string;
  mode: 'pre-build' | 'build' | 'runtime';
  verdict: 'PASSED' | 'BLOCKED' | 'WARNING';
  summary_critical: number;
  summary_high: number;
  summary_medium: number;
  summary_low: number;
  auto_fixes_available: number;
  auto_fixes_applied: number;
  duration_ms?: number;
  created_at: string;
  completed_at?: string;
}

export interface InspectionIssue {
  id: string;
  inspection_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  location?: string;
  issue: string;
  remedy?: string;
  auto_fixable: boolean;
  auto_fixed: boolean;
  fix_applied_at?: string;
  created_at: string;
}

export interface VendorConfig {
  id: string;
  vendor: string;
  rate_limit_value: number;
  rate_limit_window_ms: number;
  rate_limit_type: string;
  auth_type: string;
  auth_token_expiry_minutes?: number;
  auth_refresh_buffer_minutes?: number;
  pagination_type: string;
  pagination_gotchas: string[];
  webhook_timeout_ms: number;
  known_issues: string[];
  recommendations: string[];
  updated_at: string;
}

export function createInspection(data: Omit<InspectionRecord, 'id' | 'created_at'>): InspectionRecord {
  const database = getDatabase();
  const id = generateId('insp');
  const created_at = new Date().toISOString();

  database.prepare(`
    INSERT INTO inspections (id, build_id, server_name, server_type, industry, mode, verdict,
      summary_critical, summary_high, summary_medium, summary_low,
      auto_fixes_available, auto_fixes_applied, duration_ms, created_at, completed_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, data.build_id, data.server_name, data.server_type || null, data.industry || null,
    data.mode, data.verdict, data.summary_critical, data.summary_high,
    data.summary_medium, data.summary_low, data.auto_fixes_available,
    data.auto_fixes_applied, data.duration_ms || null, created_at, data.completed_at || null
  );

  return { ...data, id, created_at };
}

export function createInspectionIssue(data: Omit<InspectionIssue, 'id' | 'created_at'>): InspectionIssue {
  const database = getDatabase();
  const id = generateId('issue');
  const created_at = new Date().toISOString();

  database.prepare(`
    INSERT INTO inspection_issues (id, inspection_id, severity, category, location, issue, remedy, auto_fixable, auto_fixed, fix_applied_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, data.inspection_id, data.severity, data.category, data.location || null,
    data.issue, data.remedy || null, data.auto_fixable ? 1 : 0, data.auto_fixed ? 1 : 0,
    data.fix_applied_at || null, created_at
  );

  return { ...data, id, created_at };
}

export function getInspection(id: string): InspectionRecord | null {
  const database = getDatabase();
  const row = database.prepare('SELECT * FROM inspections WHERE id = ?').get(id) as InspectionRecord | undefined;
  return row || null;
}

export function getInspectionsByBuild(buildId: string): InspectionRecord[] {
  const database = getDatabase();
  return database.prepare('SELECT * FROM inspections WHERE build_id = ? ORDER BY created_at DESC').all(buildId) as InspectionRecord[];
}

export function getIssuesByInspection(inspectionId: string): InspectionIssue[] {
  const database = getDatabase();
  return database.prepare('SELECT * FROM inspection_issues WHERE inspection_id = ? ORDER BY severity, category').all(inspectionId) as InspectionIssue[];
}

export function getVendorConfig(vendor: string): VendorConfig | null {
  const database = getDatabase();
  const row = database.prepare('SELECT * FROM vendor_configs WHERE vendor = ?').get(vendor) as any;
  if (!row) return null;

  return {
    ...row,
    pagination_gotchas: JSON.parse(row.pagination_gotchas || '[]'),
    known_issues: JSON.parse(row.known_issues || '[]'),
    recommendations: JSON.parse(row.recommendations || '[]')
  };
}

export function getAllVendorConfigs(): VendorConfig[] {
  const database = getDatabase();
  const rows = database.prepare('SELECT * FROM vendor_configs ORDER BY vendor').all() as any[];

  return rows.map(row => ({
    ...row,
    pagination_gotchas: JSON.parse(row.pagination_gotchas || '[]'),
    known_issues: JSON.parse(row.known_issues || '[]'),
    recommendations: JSON.parse(row.recommendations || '[]')
  }));
}

export function getComplianceRules(regulation?: string): any[] {
  const database = getDatabase();
  if (regulation) {
    return database.prepare('SELECT * FROM compliance_rules WHERE regulation = ?').all(regulation);
  }
  return database.prepare('SELECT * FROM compliance_rules ORDER BY regulation, rule_name').all();
}

export function updateInspectionVerdict(id: string, verdict: 'PASSED' | 'BLOCKED' | 'WARNING', summary: {
  critical: number;
  high: number;
  medium: number;
  low: number;
  auto_fixes_available: number;
  auto_fixes_applied: number;
  duration_ms: number;
}): void {
  const database = getDatabase();
  const completed_at = new Date().toISOString();

  database.prepare(`
    UPDATE inspections SET
      verdict = ?,
      summary_critical = ?,
      summary_high = ?,
      summary_medium = ?,
      summary_low = ?,
      auto_fixes_available = ?,
      auto_fixes_applied = ?,
      duration_ms = ?,
      completed_at = ?
    WHERE id = ?
  `).run(
    verdict, summary.critical, summary.high, summary.medium, summary.low,
    summary.auto_fixes_available, summary.auto_fixes_applied, summary.duration_ms,
    completed_at, id
  );
}

export function recordAutoFix(data: {
  issue_id: string;
  inspection_id: string;
  fix_type: string;
  original_content?: string;
  fixed_content?: string;
  file_path?: string;
  success: boolean;
  error_message?: string;
}): string {
  const database = getDatabase();
  const id = generateId('fix');

  database.prepare(`
    INSERT INTO auto_fixes (id, issue_id, inspection_id, fix_type, original_content, fixed_content, file_path, success, error_message)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, data.issue_id, data.inspection_id, data.fix_type,
    data.original_content || null, data.fixed_content || null,
    data.file_path || null, data.success ? 1 : 0, data.error_message || null
  );

  // Mark issue as fixed if successful
  if (data.success) {
    database.prepare(`
      UPDATE inspection_issues SET auto_fixed = 1, fix_applied_at = datetime('now') WHERE id = ?
    `).run(data.issue_id);
  }

  return id;
}
