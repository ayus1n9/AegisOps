import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { checkPythonHealth, sendAnalysisToPython } from '../services/pythonClient';

const router = Router();

const AnalyzeSchema = z.object({
  targetName: z
    .string()
    .min(1, 'Target name cannot be empty')
    .max(120, 'Target name is too long')
    .regex(/^[a-zA-Z0-9_\-\.:]+$/, 'Target name contains disallowed characters')
    .refine((val) => !val.includes('..') && !val.includes('/') && !val.includes('\\'), {
      message: 'Path traversal sequences are not allowed',
    }),
  artifactType: z.enum(['container_image', 'source_code', 'configuration']),
  environment: z.enum(['development', 'staging', 'production']).default('production'),
  parameters: z.record(z.unknown()).optional().default({}),
});

// GET /api/v1/status
router.get('/status', async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const pythonHealth = await checkPythonHealth();
    res.status(200).json({
      system: 'AegisOps DevSecOps Platform',
      version: '1.0.0',
      status: pythonHealth.available ? 'operational' : 'degraded',
      services: {
        api: { status: 'healthy', version: '1.0.0' },
        pythonService: pythonHealth,
      },
      uptimeSeconds: Math.floor(process.uptime()),
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/v1/analyze
router.post('/analyze', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const validated = AnalyzeSchema.parse(req.body);

    const pythonResult = await sendAnalysisToPython({
      target_name: validated.targetName,
      artifact_type: validated.artifactType,
      environment: validated.environment,
      parameters: validated.parameters,
    });

    res.status(200).json({
      success: true,
      data: pythonResult,
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/v1/metrics
router.get('/metrics', (_req: Request, res: Response) => {
  const mem = process.memoryUsage();
  res.status(200).json({
    uptime: process.uptime(),
    memory: {
      rssMb: Math.round(mem.rss / 1024 / 1024),
      heapTotalMb: Math.round(mem.heapTotal / 1024 / 1024),
      heapUsedMb: Math.round(mem.heapUsed / 1024 / 1024),
    },
  });
});

export const apiRoutes = router;
