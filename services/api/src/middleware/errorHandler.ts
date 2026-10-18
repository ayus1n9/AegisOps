import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';

export function errorHandler(
  err: Error,
  _req: Request,
  res: Response,
  _next: NextFunction
): void {
  // Handle Zod validation errors
  if (err instanceof ZodError) {
    res.status(400).json({
      error: 'Validation Error',
      message: 'Input validation failed against security schema',
      details: err.errors.map((e) => ({
        field: e.path.join('.'),
        issue: e.message,
      })),
    });
    return;
  }

  // Generic sanitized error response (never leak internal stack trace)
  console.error('[AegisOps API Error]:', err.message);
  res.status(500).json({
    error: 'Internal Server Error',
    message: 'An unexpected security-monitored error occurred.',
  });
}
