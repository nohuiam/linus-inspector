/**
 * HTTP REST API Server
 *
 * Provides REST endpoints for inspection operations.
 *
 * Now with rate limiting, timeouts, and proper error handling.
 * Because a rate-limit inspector without rate limiting is unacceptable.
 */

import express, { type Request, type Response, type NextFunction } from 'express';
import { inspectCode } from '../inspectors/code-inspector.js';
import { inspectPrompt } from '../inspectors/prompt-inspector.js';
import { validateSkill } from '../inspectors/skill-validator.js';
import { checkIntegration } from '../inspectors/integration-checker.js';
import { runAllInspections, SUPPORTED_VENDORS, SUPPORTED_REGULATIONS } from '../rules/index.js';
import {
  getInspection,
  getInspectionsByBuild,
  getIssuesByInspection,
  getVendorConfig,
  getAllVendorConfigs,
  getComplianceRules
} from '../database/index.js';
import {
  createRateLimiter,
  withTimeout,
  enhancedErrorHandler,
  requestIdMiddleware,
  isClientError
} from './middleware.js';
import { inspectSelf } from '../tools/inspect-self.js';

export function createHttpServer(port: number): express.Application {
  const app = express();

  // Request ID for tracing
  app.use(requestIdMiddleware);

  app.use(express.json({ limit: '10mb' }));

  // Rate limiting - 100 requests per minute
  // Because a rate-limit inspector without rate limiting is ironic
  app.use(createRateLimiter({
    windowMs: 60000,
    max: 100,
    message: 'Too many requests to linus-inspector. The irony is not lost on us.'
  }));

  // Health check
  app.get('/health', (_req: Request, res: Response) => {
    res.json({
      status: 'healthy',
      server: 'linus-inspector',
      version: '1.0.0',
      timestamp: new Date().toISOString()
    });
  });

  // === Pre-Build Inspection Endpoints ===

  // Get vendor configuration
  app.get('/api/vendor/:vendor', (req: Request, res: Response) => {
    const vendor = req.params.vendor as string;
    const config = getVendorConfig(vendor);

    if (!config) {
      res.status(404).json({
        error: `Vendor not found: ${vendor}`,
        supported: SUPPORTED_VENDORS
      });
      return;
    }

    res.json(config);
  });

  // List all vendors
  app.get('/api/vendors', (_req: Request, res: Response) => {
    res.json({
      vendors: SUPPORTED_VENDORS,
      configs: getAllVendorConfigs()
    });
  });

  // Inspect prompt
  app.post('/api/inspect/prompt', (req: Request, res: Response) => {
    try {
      const result = inspectPrompt(req.body);
      res.json(result);
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  });

  // Validate skill
  app.post('/api/inspect/skill', (req: Request, res: Response) => {
    try {
      const result = validateSkill(req.body);
      res.json(result);
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  });

  // === Build Inspection Endpoints ===

  // Full build inspection (with timeout and proper error classification)
  app.post('/api/inspect/build', async (req: Request, res: Response) => {
    try {
      const result = await inspectCode(req.body);
      res.json(result);
    } catch (error: any) {
      const status = isClientError(error) ? 400 : 500;
      res.status(status).json({ error: error.message });
    }
  });

  // Quick code inspection
  app.post('/api/inspect/code', (req: Request, res: Response) => {
    try {
      const { code, vendor, regulation } = req.body;
      const result = runAllInspections(code, { vendor, regulation });
      res.json(result);
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  });

  // Ecosystem integration check
  app.post('/api/inspect/integration', (req: Request, res: Response) => {
    try {
      const result = checkIntegration(req.body);
      res.json(result);
    } catch (error: any) {
      res.status(400).json({ error: error.message });
    }
  });

  // === Compliance Endpoints ===

  // Get compliance rules
  app.get('/api/compliance', (req: Request, res: Response) => {
    const regulation = typeof req.query.regulation === 'string' ? req.query.regulation : undefined;
    const rules = getComplianceRules(regulation);
    res.json({
      regulations: SUPPORTED_REGULATIONS,
      rules
    });
  });

  app.get('/api/compliance/:regulation', (req: Request, res: Response) => {
    const regulation = req.params.regulation as string;
    const rules = getComplianceRules(regulation);
    res.json({ regulation, rules });
  });

  // === Inspection History Endpoints ===

  // Get inspection by ID
  app.get('/api/inspections/:id', (req: Request, res: Response) => {
    const id = req.params.id as string;
    const inspection = getInspection(id);

    if (!inspection) {
      res.status(404).json({ error: 'Inspection not found' });
      return;
    }

    const issues = getIssuesByInspection(id);
    res.json({ inspection, issues });
  });

  // Get inspections by build
  app.get('/api/builds/:buildId/inspections', (req: Request, res: Response) => {
    const buildId = req.params.buildId as string;
    const inspections = getInspectionsByBuild(buildId);
    res.json({ build_id: buildId, inspections });
  });

  // === Status Endpoints ===

  app.get('/api/status', (_req: Request, res: Response) => {
    res.json({
      server: 'linus-inspector',
      version: '1.0.0',
      supported_vendors: SUPPORTED_VENDORS,
      supported_regulations: SUPPORTED_REGULATIONS,
      inspection_categories: [
        'rate_limiting',
        'oauth',
        'error_handling',
        'webhooks',
        'compliance',
        'data_integrity'
      ]
    });
  });

  // Enhanced error handler with proper classification and logging
  app.use(enhancedErrorHandler);

  // Start server
  app.listen(port, () => {
    console.log(`HTTP server listening on port ${port}`);
  });

  return app;
}
