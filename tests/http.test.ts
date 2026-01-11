/**
 * Tests for HTTP middleware and server
 */

import { describe, it, expect } from 'vitest';
import {
  createRateLimiter,
  isClientError,
  getErrorStatus
} from '../src/http/middleware.js';

describe('Rate Limiter', () => {
  it('should create rate limiter with options', () => {
    const limiter = createRateLimiter({
      windowMs: 60000,
      max: 100,
      message: 'Too many requests'
    });
    expect(typeof limiter).toBe('function');
  });

  it('should allow requests under limit', () => {
    const limiter = createRateLimiter({
      windowMs: 60000,
      max: 5
    });

    // Mock request/response
    const req: any = { ip: '127.0.0.1', headers: {} };
    const res: any = {
      statusCode: 200,
      headers: {},
      setHeader: function(key: string, value: string) { this.headers[key] = value; },
      status: function(code: number) { this.statusCode = code; return this; },
      json: function() { return this; },
      on: function() {}
    };
    let nextCalled = false;
    const next = () => { nextCalled = true; };

    // First request should pass
    limiter(req, res, next);
    expect(nextCalled).toBe(true);
    expect(res.statusCode).toBe(200);
    expect(res.headers['X-RateLimit-Remaining']).toBe('4');
  });

  it('should block requests over limit', () => {
    const limiter = createRateLimiter({
      windowMs: 60000,
      max: 2
    });

    const req: any = { ip: '192.168.1.1', headers: {} };
    const res: any = {
      statusCode: 200,
      headers: {},
      body: null,
      setHeader: function(key: string, value: string) { this.headers[key] = value; },
      status: function(code: number) { this.statusCode = code; return this; },
      json: function(data: any) { this.body = data; return this; },
      on: function() {}
    };

    // Use up the limit
    limiter(req, res, () => {});
    limiter(req, res, () => {});

    // Third request should be blocked
    let nextCalled = false;
    limiter(req, res, () => { nextCalled = true; });

    expect(nextCalled).toBe(false);
    expect(res.statusCode).toBe(429);
    expect(res.body.error).toContain('Too many requests');
    expect(res.body.retryAfter).toBeDefined();
  });
});

describe('Error Classification', () => {
  it('should classify validation errors as client errors', () => {
    const validationError = new Error('ValidationError');
    validationError.name = 'ValidationError';
    expect(isClientError(validationError)).toBe(true);
  });

  it('should classify ZodError as client error', () => {
    const zodError = new Error('ZodError');
    zodError.name = 'ZodError';
    expect(isClientError(zodError)).toBe(true);
  });

  it('should classify missing field errors as client errors', () => {
    const error = new Error('Required field missing: name');
    expect(isClientError(error)).toBe(true);
  });

  it('should classify invalid parameter errors as client errors', () => {
    const error = new Error('Invalid parameter: port must be a number');
    expect(isClientError(error)).toBe(true);
  });

  it('should not classify generic errors as client errors', () => {
    const error = new Error('Something went wrong internally');
    expect(isClientError(error)).toBe(false);
  });
});

describe('Error Status Mapping', () => {
  it('should return 400 for client errors', () => {
    const error = new Error('Missing required field');
    expect(getErrorStatus(error)).toBe(400);
  });

  it('should return 404 for not found errors', () => {
    const error = new Error('Resource not found');
    expect(getErrorStatus(error)).toBe(404);
  });

  it('should return 401 for authentication errors', () => {
    const error = new Error('Authentication failed');
    expect(getErrorStatus(error)).toBe(401);
  });

  it('should return 403 for permission errors', () => {
    const error = new Error('Permission denied');
    expect(getErrorStatus(error)).toBe(403);
  });

  it('should return 408 for timeout errors', () => {
    const error = new Error('Request timeout');
    expect(getErrorStatus(error)).toBe(408);
  });

  it('should return 500 for unknown errors', () => {
    const error = new Error('Internal failure');
    expect(getErrorStatus(error)).toBe(500);
  });
});
