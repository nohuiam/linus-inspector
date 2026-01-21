/**
 * Linus Inspector - Inspector Modules Index
 *
 * Exports all inspector modules:
 * - Code Inspector (build mode)
 * - Prompt Inspector (pre-build mode)
 * - Skill Validator (pre-build mode)
 * - Integration Checker (build mode)
 * - Server Profiler (profile detection)
 */

export * from './code-inspector.js';
export * from './prompt-inspector.js';
export * from './skill-validator.js';
export * from './integration-checker.js';

// Re-export profiler
export { detectServerProfile, detectProfileFromCode } from '../profiler/index.js';
export type { ServerProfile, ServerType, RuleApplicability } from '../profiler/index.js';
