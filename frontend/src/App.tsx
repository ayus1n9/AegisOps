import React, { useEffect, useState, useCallback } from 'react';
import { StatusCard } from './components/StatusCard';
import { AnalyzeForm } from './components/AnalyzeForm';
import { FindingsList } from './components/FindingsList';
import { SystemStatus, AnalysisResponseData } from './types';

const API_BASE = (import.meta as any).env?.VITE_API_BASE_URL || 'http://localhost:8000';

export const App: React.FC = () => {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [statusLoading, setStatusLoading] = useState(false);
  const [statusError, setStatusError] = useState<string | null>(null);

  const [analysisResult, setAnalysisResult] = useState<AnalysisResponseData | null>(null);
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);

  const fetchStatus = useCallback(async () => {
    setStatusLoading(true);
    setStatusError(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/status`);
      if (!res.ok) {
        throw new Error(`API responded with status ${res.status}`);
      }
      const data: SystemStatus = await res.json();
      setStatus(data);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to reach API gateway';
      setStatusError(`Connection failure: ${msg}`);
      setStatus(null);
    } finally {
      setStatusLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  const handleAnalyze = async (
    targetName: string,
    artifactType: string,
    parameters: Record<string, unknown>
  ) => {
    setAnalysisLoading(true);
    setAnalysisError(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetName,
          artifactType,
          environment: 'production',
          parameters,
        }),
      });

      if (!res.ok) {
        const errorBody = await res.json().catch(() => ({}));
        throw new Error(errorBody.message || `API error code ${res.status}`);
      }

      const resJson = await res.json();
      setAnalysisResult(resJson.data);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Security analysis request failed';
      setAnalysisError(msg);
    } finally {
      setAnalysisLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: '1100px', margin: '0 auto', padding: '2rem 1rem' }}>
      <header style={{ marginBottom: '2rem', borderBottom: '1px solid #334155', paddingBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h1 style={{ margin: 0, fontSize: '1.75rem', fontWeight: 700, letterSpacing: '-0.025em' }}>
              SecureFlow <span style={{ color: '#38bdf8', fontSize: '1rem', fontWeight: 400 }}>DevSecOps Pipeline</span>
            </h1>
            <p style={{ margin: '0.25rem 0 0 0', color: '#94a3b8', fontSize: '0.875rem' }}>
              Automated Secret Scanning, SAST, SCA, Container Security, DAST & Policy Gate
            </p>
          </div>
          <div style={{ textAlign: 'right' }}>
            <span style={{ backgroundColor: '#1e293b', border: '1px solid #475569', padding: '0.35rem 0.75rem', borderRadius: '0.375rem', fontSize: '0.8125rem', color: '#cbd5e1' }}>
              CI/CD Production Mode
            </span>
          </div>
        </div>
      </header>

      <main>
        <StatusCard
          status={status}
          loading={statusLoading}
          error={statusError}
          onRefresh={fetchStatus}
        />

        <AnalyzeForm
          onSubmit={handleAnalyze}
          loading={analysisLoading}
        />

        {analysisError && (
          <div style={{ backgroundColor: '#7f1d1d', border: '1px solid #dc2626', color: '#fca5a5', padding: '1rem', borderRadius: '0.5rem', marginBottom: '1.5rem' }}>
            <strong>Analysis Failed:</strong> {analysisError}
          </div>
        )}

        {analysisResult && (
          <FindingsList
            findings={analysisResult.findings}
            riskLevel={analysisResult.risk_level}
            isReleasable={analysisResult.is_releasable}
          />
        )}
      </main>

      <footer style={{ marginTop: '3rem', paddingTop: '1.5rem', borderTop: '1px solid #1e293b', textAlign: 'center', color: '#64748b', fontSize: '0.8125rem' }}>
        SecureFlow DevSecOps Pipeline • Production Verification & Enforcement
      </footer>
    </div>
  );
};
