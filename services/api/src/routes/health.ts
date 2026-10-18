import { Router, Request, Response } from 'express';

const router = Router();

router.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({
    status: 'healthy',
    service: 'aegisops-api',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
  });
});

router.get('/ready', (_req: Request, res: Response) => {
  res.status(200).json({
    status: 'ready',
    ready: true,
  });
});

export const healthRoutes = router;
