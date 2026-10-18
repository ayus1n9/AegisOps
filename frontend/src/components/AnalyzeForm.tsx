import React, { useState } from 'react';

interface AnalyzeFormProps {
  onSubmit: (targetName: string, artifactType: string, parameters: Record<string, unknown>) => void;
  loading: boolean;
}

export const AnalyzeForm: React.FC<AnalyzeFormProps> = ({ onSubmit, loading }) => {
  const [targetName, setTargetName] = useState('aegisops-service:1.0.0');
  const [artifactType, setArtifactType] = useState('container_image');
  const [runAsRoot, setRunAsRoot] = useState(false);
  const [debugMode, setDebugMode] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);

    // Client-side sanitization and validation check
    const cleanTarget = targetName.trim();
    if (!cleanTarget) {
      setValidationError('Target identifier is required.');
      return;
    }
    if (cleanTarget.includes('..') || cleanTarget.includes('/') || cleanTarget.includes('\\')) {
      setValidationError('Invalid target name: path traversal characters are forbidden.');
      return;
    }

    onSubmit(cleanTarget, artifactType, {
      run_as_root: runAsRoot,
      debug: debugMode,
    });
  };

  return (
    <div style={{ backgroundColor: '#1e293b', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid #334155', marginBottom: '1.5rem' }}>
      <h2 style={{ margin: '0 0 1rem 0', fontSize: '1.25rem', fontWeight: 600 }}>Run Security Target Analysis</h2>
      
      {validationError && (
        <div style={{ backgroundColor: '#7f1d1d', color: '#fca5a5', padding: '0.75rem', borderRadius: '0.375rem', marginBottom: '1rem', fontSize: '0.875rem' }}>
          {validationError}
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem', marginBottom: '1rem' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.875rem', color: '#94a3b8' }}>Target Identifier</label>
            <input
              type="text"
              value={targetName}
              onChange={(e) => setTargetName(e.target.value)}
              placeholder="e.g. app-container:1.0.0"
              style={{
                width: '100%',
                boxSizing: 'border-box',
                padding: '0.625rem',
                borderRadius: '0.375rem',
                backgroundColor: '#0f172a',
                border: '1px solid #334155',
                color: '#fff',
              }}
            />
          </div>

          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.875rem', color: '#94a3b8' }}>Artifact Type</label>
            <select
              value={artifactType}
              onChange={(e) => setArtifactType(e.target.value)}
              style={{
                width: '100%',
                boxSizing: 'border-box',
                padding: '0.625rem',
                borderRadius: '0.375rem',
                backgroundColor: '#0f172a',
                border: '1px solid #334155',
                color: '#fff',
              }}
            >
              <option value="container_image">Container Image</option>
              <option value="source_code">Source Code</option>
              <option value="configuration">Configuration</option>
            </select>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '1.5rem', marginBottom: '1.25rem' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.875rem' }}>
            <input
              type="checkbox"
              checked={runAsRoot}
              onChange={(e) => setRunAsRoot(e.target.checked)}
            />
            Simulate Root User Flag (Violation Test)
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.875rem' }}>
            <input
              type="checkbox"
              checked={debugMode}
              onChange={(e) => setDebugMode(e.target.checked)}
            />
            Simulate Debug in Prod (Violation Test)
          </label>
        </div>

        <button
          type="submit"
          disabled={loading}
          style={{
            backgroundColor: '#10b981',
            color: '#fff',
            border: 'none',
            padding: '0.625rem 1.25rem',
            borderRadius: '0.375rem',
            fontWeight: 600,
            cursor: loading ? 'not-allowed' : 'pointer',
            opacity: loading ? 0.7 : 1,
          }}
        >
          {loading ? 'Evaluating Policy...' : 'Evaluate Security Policy'}
        </button>
      </form>
    </div>
  );
};
