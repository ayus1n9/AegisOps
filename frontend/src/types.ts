export type RiskLevel = 'CLEAN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface SecurityFinding {
  rule_id: string;
  title: string;
  severity: RiskLevel;
  description: string;
  remediation: string;
}

export interface AnalysisResponseData {
  analysis_id: string;
  target_name: string;
  artifact_type: string;
  environment: string;
  risk_level: RiskLevel;
  is_releasable: boolean;
  findings_count: number;
  findings: SecurityFinding[];
  evaluated_at: string;
}

export interface SystemStatus {
  system: string;
  version: string;
  status: 'operational' | 'degraded' | 'unavailable';
  services: {
    api: { status: string; version: string };
    pythonService: { status: string; service?: string; version?: string; available: boolean };
  };
  uptimeSeconds: number;
}
