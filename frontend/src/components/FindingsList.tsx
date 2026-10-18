import React from 'react';
import { SecurityFinding, RiskLevel } from '../types';

interface FindingsListProps {
  findings: SecurityFinding[];
  riskLevel: RiskLevel;
  isReleasable: boolean;
}

const severityColors: Record<RiskLevel, { bg: string; text: string; border: string }> = {
  CLEAN: { bg: '#064e3b', text: '#6ee7b7', border: '#059669' },
  LOW: { bg: '#1e3a8a', text: '#93c5fd', border: '#3b82f6' },
  MEDIUM: { bg: '#713f12', text: '#fde047', border: '#ca8a04' },
  HIGH: { bg: '#831843', text: '#fbcfe8', border: '#db2777' },
  CRITICAL: { bg: '#7f1d1d', text: '#fca5a5', border: '#dc2626' },
};

export const FindingsList: React.FC<FindingsListProps> = ({ findings, riskLevel, isReleasable }) => {
  const colors = severityColors[riskLevel] || severityColors.LOW;

  return (
    <div style={{ backgroundColor: '#1e293b', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid #334155' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h2 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 600 }}>Security Evaluation Results</h2>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <span style={{ backgroundColor: colors.bg, color: colors.text, border: `1px solid ${colors.border}`, padding: '0.25rem 0.75rem', borderRadius: '9999px', fontSize: '0.875rem', fontWeight: 600 }}>
            Risk: {riskLevel}
          </span>
          <span style={{ backgroundColor: isReleasable ? '#064e3b' : '#7f1d1d', color: isReleasable ? '#6ee7b7' : '#fca5a5', border: `1px solid ${isReleasable ? '#059669' : '#dc2626'}`, padding: '0.25rem 0.75rem', borderRadius: '9999px', fontSize: '0.875rem', fontWeight: 600 }}>
            {isReleasable ? 'Release Allowed' : 'Release Blocked'}
          </span>
        </div>
      </div>

      {findings.length === 0 ? (
        <div style={{ backgroundColor: '#0f172a', padding: '1.5rem', borderRadius: '0.5rem', textAlign: 'center', color: '#94a3b8' }}>
          No security violations or policy breaches detected in this target.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {findings.map((f, i) => (
            <div key={i} style={{ backgroundColor: '#0f172a', padding: '1rem', borderRadius: '0.5rem', borderLeft: `4px solid ${severityColors[f.severity]?.border || '#ef4444'}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <span style={{ fontWeight: 600, fontSize: '1rem' }}>{f.title}</span>
                <span style={{ fontSize: '0.75rem', backgroundColor: '#334155', padding: '0.2rem 0.5rem', borderRadius: '0.25rem' }}>
                  {f.rule_id}
                </span>
              </div>
              <p style={{ margin: '0 0 0.5rem 0', color: '#cbd5e1', fontSize: '0.875rem' }}>{f.description}</p>
              <div style={{ fontSize: '0.8125rem', color: '#38bdf8' }}>
                <strong>Remediation:</strong> {f.remediation}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
