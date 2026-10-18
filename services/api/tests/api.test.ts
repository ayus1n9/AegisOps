import request from 'supertest';
import { app } from '../src/app';
import * as pythonClient from '../src/services/pythonClient';

describe('SecureFlow API Service Tests', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Health and Readiness Endpoints', () => {
    it('GET /health should return 200 and healthy status', async () => {
      const res = await request(app).get('/health');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('healthy');
      expect(res.body.service).toBe('secureflow-api');
    });

    it('GET /ready should return 200 and ready state', async () => {
      const res = await request(app).get('/ready');
      expect(res.status).toBe(200);
      expect(res.body.ready).toBe(true);
    });

    it('should include strict security headers via Helmet', async () => {
      const res = await request(app).get('/health');
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['x-frame-options']).toBe('SAMEORIGIN');
    });
  });

  describe('API Endpoints /api/v1', () => {
    it('GET /api/v1/status should return system status with python service health', async () => {
      jest.spyOn(pythonClient, 'checkPythonHealth').mockResolvedValue({
        status: 'healthy',
        service: 'secureflow-python-service',
        version: '1.0.0',
        available: true,
      });

      const res = await request(app).get('/api/v1/status');
      expect(res.status).toBe(200);
      expect(res.body.status).toBe('operational');
      expect(res.body.services.api.status).toBe('healthy');
      expect(res.body.services.pythonService.available).toBe(true);
    });

    it('GET /api/v1/metrics should return memory metrics', async () => {
      const res = await request(app).get('/api/v1/metrics');
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('uptime');
      expect(res.body.memory).toHaveProperty('rssMb');
    });

    it('POST /api/v1/analyze should succeed with valid schema payload', async () => {
      const mockResult = {
        analysis_id: 'test-uuid-123',
        target_name: 'secureflow-api:1.0.0',
        artifact_type: 'container_image',
        environment: 'production',
        risk_level: 'CLEAN',
        is_releasable: true,
        findings_count: 0,
        findings: [],
      };

      jest.spyOn(pythonClient, 'sendAnalysisToPython').mockResolvedValue(mockResult);

      const res = await request(app)
        .post('/api/v1/analyze')
        .send({
          targetName: 'secureflow-api:1.0.0',
          artifactType: 'container_image',
          environment: 'production',
          parameters: { user: 10001 },
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.risk_level).toBe('CLEAN');
    });

    it('POST /api/v1/analyze should reject path traversal in targetName', async () => {
      const res = await request(app)
        .post('/api/v1/analyze')
        .send({
          targetName: '../../etc/passwd',
          artifactType: 'source_code',
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Validation Error');
      expect(res.body.details[0].field).toBe('targetName');
    });

    it('POST /api/v1/analyze should reject invalid artifact type', async () => {
      const res = await request(app)
        .post('/api/v1/analyze')
        .send({
          targetName: 'valid-target',
          artifactType: 'invalid_type',
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Validation Error');
    });

    it('GET /nonexistent should return sanitized 404', async () => {
      const res = await request(app).get('/unknown-endpoint');
      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Not Found');
    });
  });
});
