import React from 'react';
import { SystemStatus } from '../types';

interface StatusCardProps {
  status: SystemStatus | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
}

export const StatusCard: React.FC<StatusCardProps> = ({ status, loading, error, onRefresh }) => {
  return (
    <div style={{ backgroundColor: '#1e293b', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid #334155', marginBottom: '1.5rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h2 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 600 }}>System Health & Status</h2>
        <button
          onClick={onRefresh}
          disabled={loading}
          style={{
            backgroundColor: '#3b82f6',
            color: '#fff',
            border: 'none',
            padding: '0.5rem 1rem',
            borderRadius: '0.375rem',
            cursor: loading ? 'not-allowed' : 'pointer',
            opacity: loading ? 0.7 : 1,
            fontWeight: 500
          }}
        >
          {loading ? 'Refreshing...' : 'Refresh Status'}
        </button>
      </div>

      {error && (
        <div style={{ backgroundColor: '#7f1d1d', border: '1px solid #b91c1c', padding: '0.75rem', borderRadius: '0.375rem', marginBottom: '1rem', color: '#fecaca' }}>
          <strong>Communication Alert:</strong> {error}
        </div>
      )}

      {status && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
          <div style={{ backgroundColor: '#0f172a', padding: '1rem', borderRadius: '0.5rem', border: '1px solid #1e293b' }}>
            <div style={{ fontSize: '0.875rem', color: '#94a3b8' }}>Overall Gateway Status</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: status.status === 'operational' ? '#22c55e' : '#eab308' }}>
              {status.status.toUpperCase()}
            </div>
          </div>
          <div style={{ backgroundColor: '#0f172a', padding: '1rem', borderRadius: '0.5rem', border: '1px solid #1e293b' }}>
            <div style={{ fontSize: '0.875rem', color: '#94a3b8' }}>Node.js API</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#22c55e' }}>
              {status.services.api.status} (v{status.services.api.version})
            </div>
          </div>
          <div style={{ backgroundColor: '#0f172a', padding: '1rem', borderRadius: '0.5rem', border: '1px solid #1e293b' }}>
            <div style={{ fontSize: '0.875rem', color: '#94a3b8' }}>Python Analytics Service</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: status.services.pythonService.available ? '#22c55e' : '#ef4444' }}>
              {status.services.pythonService.status} ({status.services.pythonService.available ? 'Connected' : 'Offline'})
            </div>
          </div>
          <div style={{ backgroundColor: '#0f172a', padding: '1rem', borderRadius: '0.5rem', border: '1px solid #1e293b' }}>
            <div style={{ fontSize: '0.875rem', color: '#94a3b8' }}>Uptime</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: '#38bdf8' }}>
              {status.uptimeSeconds}s
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
