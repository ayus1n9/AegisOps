import { config } from '../config';

export interface PythonAnalyzePayload {
  target_name: string;
  artifact_type: 'container_image' | 'source_code' | 'configuration';
  environment?: string;
  parameters?: Record<string, unknown>;
}

export interface PythonServiceHealth {
  status: string;
  service?: string;
  version?: string;
  available: boolean;
}

export async function checkPythonHealth(): Promise<PythonServiceHealth> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 2000);

  try {
    const res = await fetch(`${config.pythonServiceUrl}/health`, {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = (await res.json()) as Record<string, unknown>;
      return {
        status: (data.status as string) || 'healthy',
        service: (data.service as string) || 'python-service',
        version: (data.version as string) || '1.0.0',
        available: true,
      };
    }
    return { status: 'unhealthy', available: false };
  } catch (_err) {
    clearTimeout(timeoutId);
    return { status: 'unavailable', available: false };
  }
}

export async function sendAnalysisToPython(
  payload: PythonAnalyzePayload
): Promise<Record<string, unknown>> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const res = await fetch(`${config.pythonServiceUrl}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(`Python service returned status ${res.status}: ${JSON.stringify(errorData)}`);
    }

    return (await res.json()) as Record<string, unknown>;
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    const message = err instanceof Error ? err.message : 'Unknown communication error';
    throw new Error(`Failed to communicate with security analytics service: ${message}`);
  }
}
