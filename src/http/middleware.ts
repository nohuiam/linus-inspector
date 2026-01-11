/**
 * HTTP Middleware Module
 *
 * Provides rate limiting, request timeout, and enhanced error handling.
 * Because a rate-limit inspector without rate limiting is unacceptable.
 */

import { type Request, type Response, type NextFunction, type RequestHandler } from 'express';

// ============================================================================
// Types
// ============================================================================

export interface RateLimitOptions {
  windowMs: number;      // Time window in milliseconds
  max: number;           // Max requests per window
  message?: string;      // Custom 429 message
  skipFailedRequests?: boolean;
  keyGenerator?: (req: Request) => string;
}

export interface TimeoutOptions {
  ms: number;
  message?: string;
}

interface RateLimitStore {
  [key: string]: {
    count: number;
    resetTime: number;
  };
}

// ============================================================================
// Rate Limiter
// ============================================================================

/**
 * Create rate limiting middleware
 *
 * Uses sliding window algorithm with in-memory store.
 * For production, consider redis-backed store.
 */
export function createRateLimiter(options: RateLimitOptions): RequestHandler {
  const {
    windowMs,
    max,
    message = 'Too many requests, please try again later',
    skipFailedRequests = false,
    keyGenerator = (req: Request) => req.ip || 'unknown'
  } = options;

  const store: RateLimitStore = {};

  // Cleanup expired entries periodically
  setInterval(() => {
    const now = Date.now();
    for (const key in store) {
      if (store[key].resetTime < now) {
        delete store[key];
      }
    }
  }, windowMs);

  return (req: Request, res: Response, next: NextFunction): void => {
    const key = keyGenerator(req);
    const now = Date.now();

    // Initialize or reset if window expired
    if (!store[key] || store[key].resetTime < now) {
      store[key] = {
        count: 0,
        resetTime: now + windowMs
      };
    }

    const entry = store[key];
    entry.count++;

    // Set rate limit headers
    res.setHeader('X-RateLimit-Limit', max.toString());
    res.setHeader('X-RateLimit-Remaining', Math.max(0, max - entry.count).toString());
    res.setHeader('X-RateLimit-Reset', Math.ceil(entry.resetTime / 1000).toString());

    if (entry.count > max) {
      res.status(429).json({
        error: message,
        retryAfter: Math.ceil((entry.resetTime - now) / 1000)
      });
      return;
    }

    // Optionally decrement on failed requests
    if (skipFailedRequests) {
      res.on('finish', () => {
        if (res.statusCode >= 400) {
          entry.count = Math.max(0, entry.count - 1);
        }
      });
    }

    next();
  };
}

// ============================================================================
// Request Timeout
// ============================================================================

/**
 * Create request timeout wrapper for async handlers
 *
 * Wraps an async handler with a timeout. If the handler doesn't
 * respond within the timeout, returns 408 Request Timeout.
 */
export function createRequestTimeout(ms: number): (
  handler: (req: Request, res: Response, next: NextFunction) => Promise<void>
) => RequestHandler {
  return (handler) => {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const timeoutId = setTimeout(() => {
        if (!res.headersSent) {
          res.status(408).json({
            error: 'Request timeout',
            message: `Request did not complete within ${ms}ms`
          });
        }
      }, ms);

      try {
        await handler(req, res, next);
      } catch (error) {
        next(error);
      } finally {
        clearTimeout(timeoutId);
      }
    };
  };
}

/**
 * Wrap an async handler with timeout (simpler API)
 */
export function withTimeout<T>(
  handler: (req: Request, res: Response) => Promise<T>,
  ms: number
): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const timeoutId = setTimeout(() => {
      if (!res.headersSent) {
        res.status(408).json({
          error: 'Request timeout',
          message: `Request did not complete within ${ms}ms`
        });
      }
    }, ms);

    try {
      await handler(req, res);
    } catch (error) {
      if (!res.headersSent) {
        next(error);
      }
    } finally {
      clearTimeout(timeoutId);
    }
  };
}

// ============================================================================
// Error Classification
// ============================================================================

/**
 * Check if an error is a validation/client error (400)
 * vs an internal server error (500)
 */
export function isClientError(error: Error): boolean {
  const message = error.message.toLowerCase();

  // Validation errors
  if (error.name === 'ValidationError' || error.name === 'ZodError') {
    return true;
  }

  // Common validation error patterns
  const clientErrorPatterns = [
    'required',
    'invalid',
    'missing',
    'must be',
    'cannot be',
    'not found',
    'does not exist',
    'malformed',
    'bad request',
    'path',
    'parameter',
    'argument'
  ];

  return clientErrorPatterns.some(pattern => message.includes(pattern));
}

/**
 * Get appropriate HTTP status code for an error
 */
export function getErrorStatus(error: Error): number {
  const message = error.message.toLowerCase();

  // Check specific status codes FIRST (most specific to least specific)
  if (message.includes('not found') || message.includes('does not exist')) {
    return 404;
  }

  if (message.includes('unauthorized') || message.includes('authentication')) {
    return 401;
  }

  if (message.includes('forbidden') || message.includes('permission')) {
    return 403;
  }

  if (message.includes('timeout')) {
    return 408;
  }

  if (message.includes('conflict')) {
    return 409;
  }

  // Generic client error check (validation, missing params, etc.)
  if (isClientError(error)) {
    return 400;
  }

  return 500;
}

// ============================================================================
// Enhanced Error Handler
// ============================================================================

/**
 * Enhanced error handler middleware
 *
 * Logs full request context and classifies errors appropriately.
 */
export function enhancedErrorHandler(
  err: Error,
  req: Request,
  res: Response,
  _next: NextFunction
): void {
  const status = getErrorStatus(err);
  const requestId = req.headers['x-request-id'] || generateRequestId();

  // Log with full context
  console.error({
    timestamp: new Date().toISOString(),
    requestId,
    method: req.method,
    path: req.path,
    query: req.query,
    status,
    error: err.message,
    stack: process.env.NODE_ENV !== 'production' ? err.stack : undefined
  });

  // Don't send response if already sent
  if (res.headersSent) {
    return;
  }

  // Send error response
  res.status(status).json({
    error: status >= 500 ? 'Internal server error' : err.message,
    requestId,
    ...(process.env.NODE_ENV !== 'production' && status >= 500 && { details: err.message })
  });
}

/**
 * Generate a unique request ID
 */
function generateRequestId(): string {
  return `req-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 8)}`;
}

// ============================================================================
// Request ID Middleware
// ============================================================================

/**
 * Add request ID to all requests
 */
export function requestIdMiddleware(req: Request, res: Response, next: NextFunction): void {
  const requestId = (req.headers['x-request-id'] as string) || generateRequestId();
  req.headers['x-request-id'] = requestId;
  res.setHeader('X-Request-ID', requestId);
  next();
}
