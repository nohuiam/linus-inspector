/**
 * InterLock Signal Handlers
 *
 * Handles incoming signals from the mesh network.
 */

import type dgram from 'dgram';
import type { BaNanoMessage } from './protocol.js';
import { SIGNALS, getSignalName } from './protocol.js';
import { InterlockSocket } from './socket.js';
import { inspectCode } from '../inspectors/code-inspector.js';
import { inspectPrompt } from '../inspectors/prompt-inspector.js';
import { validateSkill } from '../inspectors/skill-validator.js';

export function registerHandlers(socket: InterlockSocket): void {
  // Log all incoming messages
  socket.onAny((message: BaNanoMessage, rinfo: dgram.RemoteInfo) => {
    console.log(`[InterLock] Received ${getSignalName(message.signalType)} from ${rinfo.port}`);
  });

  // Handle BUILD_STARTED
  socket.on(SIGNALS.BUILD_STARTED, async (message: BaNanoMessage, rinfo: dgram.RemoteInfo) => {
    console.log(`[BUILD_STARTED] Build ${message.payload?.build_id} started`);
    // Could notify experience-layer to prepare lessons query
    if (message.payload?.build_id) {
      socket.sendToPeer('experience-layer', SIGNALS.BUILD_STARTED, {
        build_id: message.payload.build_id,
        source: 'linus-inspector',
        timestamp: Date.now()
      });
    }
  });

  // Handle INSPECTION_REQUESTED
  socket.on(SIGNALS.INSPECTION_REQUESTED, async (message: BaNanoMessage, rinfo: dgram.RemoteInfo) => {
    console.log(`[INSPECTION_REQUESTED] Inspecting ${message.payload?.server_path}`);

    try {
      const result = await inspectCode({
        server_path: message.payload.server_path,
        server_name: message.payload.server_name,
        server_type: message.payload.server_type,
        vendor: message.payload.vendor,
        regulation: message.payload.regulation,
        industry: message.payload.industry,
        build_id: message.payload.build_id
      });

      // Send result based on verdict
      const signalType = result.verdict === 'PASSED'
        ? SIGNALS.INSPECTION_PASSED
        : SIGNALS.INSPECTION_FAILED;

      socket.send(signalType, {
        inspection_id: result.inspection_id,
        build_id: result.build_id,
        server_name: result.server_name,
        verdict: result.verdict,
        summary: result.summary,
        issues_count: result.issues.length
      }, rinfo.port);

      // Also notify experience-layer
      socket.sendToPeer('experience-layer', signalType, {
        inspection_id: result.inspection_id,
        build_id: result.build_id,
        verdict: result.verdict,
        summary: result.summary
      });

      // Extract lessons from critical/high issues
      if (result.verdict === 'BLOCKED') {
        for (const issue of result.issues.filter(i => i.severity === 'CRITICAL' || i.severity === 'HIGH')) {
          socket.sendToPeer('experience-layer', SIGNALS.LESSON_EXTRACTED, {
            inspection_id: result.inspection_id,
            category: issue.category,
            pattern: issue.issue,
            remedy: issue.remedy,
            source: 'linus_inspection',
            confidence: 0.9
          });
        }
      }

    } catch (error: any) {
      console.error('[INSPECTION_REQUESTED] Error:', error);
      socket.send(SIGNALS.INSPECTION_FAILED, {
        error: error.message,
        build_id: message.payload?.build_id
      }, rinfo.port);
    }
  });

  // Handle PRE_INSPECTION_REQUESTED (SaaS API probe)
  socket.on(SIGNALS.PRE_INSPECTION_REQUESTED, async (message: BaNanoMessage, rinfo: dgram.RemoteInfo) => {
    console.log(`[PRE_INSPECTION_REQUESTED] Probing ${message.payload?.vendor}`);

    try {
      const { getVendorConfig } = await import('../database/index.js');
      const config = getVendorConfig(message.payload.vendor);

      socket.send(SIGNALS.PRE_INSPECTION_COMPLETE, {
        vendor: message.payload.vendor,
        config,
        request_id: message.payload.request_id
      }, rinfo.port);

    } catch (error: any) {
      console.error('[PRE_INSPECTION_REQUESTED] Error:', error);
      socket.send(SIGNALS.PRE_INSPECTION_COMPLETE, {
        vendor: message.payload?.vendor,
        error: error.message
      }, rinfo.port);
    }
  });

  // Handle SKILL_VALIDATION_REQUESTED
  socket.on(SIGNALS.SKILL_VALIDATION_REQUESTED, async (message: BaNanoMessage, rinfo: dgram.RemoteInfo) => {
    console.log(`[SKILL_VALIDATION_REQUESTED] Validating skill`);

    try {
      const result = validateSkill({
        skill_path: message.payload.skill_path,
        skill_content: message.payload.skill_content,
        skill_name: message.payload.skill_name
      });

      socket.send(SIGNALS.PRE_INSPECTION_COMPLETE, {
        type: 'skill_validation',
        result,
        request_id: message.payload.request_id
      }, rinfo.port);

    } catch (error: any) {
      console.error('[SKILL_VALIDATION_REQUESTED] Error:', error);
      socket.send(SIGNALS.PRE_INSPECTION_COMPLETE, {
        type: 'skill_validation',
        error: error.message
      }, rinfo.port);
    }
  });

  // Handle PROMPT_VALIDATION_REQUESTED
  socket.on(SIGNALS.PROMPT_VALIDATION_REQUESTED, async (message: BaNanoMessage, rinfo: dgram.RemoteInfo) => {
    console.log(`[PROMPT_VALIDATION_REQUESTED] Validating prompt`);

    try {
      const result = inspectPrompt({
        prompt_content: message.payload.prompt_content,
        prompt_id: message.payload.prompt_id,
        expected_output_format: message.payload.expected_output_format,
        use_case: message.payload.use_case
      });

      socket.send(SIGNALS.PRE_INSPECTION_COMPLETE, {
        type: 'prompt_validation',
        result,
        request_id: message.payload.request_id
      }, rinfo.port);

    } catch (error: any) {
      console.error('[PROMPT_VALIDATION_REQUESTED] Error:', error);
      socket.send(SIGNALS.PRE_INSPECTION_COMPLETE, {
        type: 'prompt_validation',
        error: error.message
      }, rinfo.port);
    }
  });

  console.log('[InterLock] Handlers registered');
}
