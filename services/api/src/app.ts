import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { config } from './config';
import { standardRateLimiter } from './middleware/rateLimiter';
import { errorHandler } from './middleware/errorHandler';
import { healthRoutes } from './routes/health';
import { apiRoutes } from './routes/api';

export const app = express();

// Security headers via Helmet
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'", config.corsOrigin],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
      },
    },
    hidePoweredBy: true,
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  })
);

// CORS configuration
app.use(
  cors({
    origin: config.corsOrigin,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  })
);

// Rate limiting
app.use(standardRateLimiter);

// Parse JSON with payload size limit (mitigate DoS payload attacks)
app.use(express.json({ limit: '100kb' }));

// Route handlers
app.use('/', healthRoutes);
app.use('/api/v1', apiRoutes);

// Catch-all 404 handler
app.use((_req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested resource does not exist.',
  });
});

// Central error handler
app.use(errorHandler);
