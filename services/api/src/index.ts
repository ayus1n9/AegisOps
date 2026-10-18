import { app } from './app';
import { config } from './config';

const server = app.listen(config.port, config.host, () => {
  console.log(`[SecureFlow API] Server running on http://${config.host}:${config.port} (${config.env})`);
});

// Graceful shutdown
const shutdown = (signal: string) => {
  console.log(`[SecureFlow API] Received ${signal}, closing server...`);
  server.close(() => {
    console.log('[SecureFlow API] Server closed successfully.');
    process.exit(0);
  });
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
