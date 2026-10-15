import React from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  AlertOctagon,
  Info,
  CheckCircle2,
  Clock,
  Compass,
  FileCheck,
  History
} from 'lucide-react';

export default function AnalysisResults({ result }) {
  if (!result) return null;

  const {
    risk_score = 0,
    risk_level = 'Low',
    hostname = '',
    scheme = '',
    port = null,
    findings = [],
    summary = '',
    recommendations = [],
    analyzed_at = '',
    engine_version = '1.0.0',
    is_mock = false,
    is_fallback_simulation = false,
    from_history = false
  } = result;

  const levelClass =
    risk_level === 'High' ? 'risk-high' : risk_level === 'Medium' ? 'risk-medium' : 'risk-low';

  const scoreClass =
    risk_level === 'High' ? 'score-high' : risk_level === 'Medium' ? 'score-medium' : 'score-low';

  const badgeClass =
    risk_level === 'High' ? 'badge-high' : risk_level === 'Medium' ? 'badge-medium' : 'badge-low';

  const RiskIcon =
    risk_level === 'High' ? AlertOctagon : risk_level === 'Medium' ? AlertTriangle : ShieldCheck;

  const formattedDate = analyzed_at
    ? new Date(analyzed_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : 'Just now';

  return (
    <div className={`results-card ${levelClass}`}>
      {/* Saved-result banner when opened from History */}
      {from_history && (
        <div style={{
          marginBottom: '1.25rem',
          padding: '0.65rem 1rem',
          borderRadius: 'var(--radius-sm)',
          background: 'rgba(56, 189, 248, 0.1)',
          border: '1px solid rgba(56, 189, 248, 0.3)',
          color: '#38bdf8',
          fontSize: '0.8rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem'
        }}>
          <History size={16} style={{ flexShrink: 0 }} />
          <span>
            Saved result from {analyzed_at ? new Date(analyzed_at).toLocaleString() : 'an earlier scan'}.
            Private parts of the link were removed when it was saved, so it can't be rescanned.
          </span>
        </div>
      )}

      {/* Simulation Banner if offline */}
      {is_mock && (
        <div style={{
          marginBottom: '1.25rem',
          padding: '0.65rem 1rem',
          borderRadius: 'var(--radius-sm)',
          background: 'rgba(245, 158, 11, 0.15)',
          border: '1px solid rgba(245, 158, 11, 0.3)',
          color: '#fbbf24',
          fontSize: '0.8rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem'
        }}>
          <Info size={16} />
          <span>
            {is_fallback_simulation
              ? 'Local Backend was unreachable. Analysis evaluated using deterministic local simulation.'
              : 'Evaluated using Local Simulation Engine (VITE_ENABLE_OFFLINE_MOCK active).'}
          </span>
        </div>
      )}

      {/* Score Overview */}
      <div className="score-overview">
        <div className="score-meta">
          <div className={`score-circle ${scoreClass}`}>
            <span className="score-num">{risk_score}</span>
            <span className="score-max">/ 100</span>
          </div>

          <div className="risk-info">
            <span className={`risk-level-badge ${badgeClass}`}>
              <RiskIcon size={14} />
              {risk_level} Risk Category
            </span>
            <h3>{risk_level === 'High' ? 'Significant Threat Indicators' : risk_level === 'Medium' ? 'Caution Advised' : 'Low Suspicion Level'}</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
              Deterministic Rule Engine · Heuristic Assessment
            </p>
          </div>
        </div>

        <div style={{ textAlign: 'right', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', justifyContent: 'flex-end' }}>
            <Clock size={13} />
            <span>{formattedDate}</span>
          </div>
          <div style={{ marginTop: '0.2rem' }}>Engine v{engine_version}</div>
        </div>
      </div>

      {/* URL Technical Metadata */}
      <div className="metadata-grid">
        <div className="meta-item">
          <div className="meta-key">Target Host</div>
          <div className="meta-val">{hostname || 'N/A'}</div>
        </div>
        <div className="meta-item">
          <div className="meta-key">Protocol Scheme</div>
          <div className="meta-val">{scheme.toUpperCase()}</div>
        </div>
        <div className="meta-item">
          <div className="meta-key">Destination Port</div>
          <div className="meta-val">{port ? port : (scheme === 'https' ? '443 (Std)' : '80 (Std)')}</div>
        </div>
        <div className="meta-item">
          <div className="meta-key">Triggered Rules</div>
          <div className="meta-val">{findings.length} Flag{findings.length !== 1 ? 's' : ''}</div>
        </div>
      </div>

      {/* Executive Summary */}
      <div className="summary-text">{summary}</div>

      {/* Findings Breakdown */}
      <div className="findings-container">
        <div className="findings-title">
          <FileCheck size={18} className="text-accent" />
          <span>Security Indicator Findings ({findings.length})</span>
        </div>

        {findings.length === 0 ? (
          <div style={{
            padding: '1.25rem',
            background: 'var(--bg-card-elevated)',
            borderRadius: 'var(--radius-md)',
            border: '1px solid var(--border-subtle)',
            color: 'var(--text-secondary)',
            fontSize: '0.9rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.6rem'
          }}>
            <CheckCircle2 size={18} color="#10b981" />
            <span>All static heuristic checks passed. No known suspicious structural patterns found.</span>
          </div>
        ) : (
          findings.map((item, idx) => {
            const sevBadgeClass =
              item.severity === 'HIGH' || item.severity === 'CRITICAL'
                ? 'badge-high'
                : item.severity === 'MEDIUM'
                ? 'badge-medium'
                : 'badge-low';

            return (
              <div key={idx} className="finding-card">
                <div className="finding-header">
                  <div className="finding-title-wrap">
                    <span className={`risk-level-badge ${sevBadgeClass}`} style={{ fontSize: '0.7rem', padding: '0.15rem 0.5rem' }}>
                      {item.severity} (+{item.score_impact})
                    </span>
                    <span>{item.title}</span>
                  </div>
                  <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                    {item.rule_id}
                  </span>
                </div>
                <div className="finding-desc">{item.description}</div>
                {item.recommendation && (
                  <div className="finding-rec">
                    <strong>Action: </strong> {item.recommendation}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Recommended Precautions */}
      {recommendations.length > 0 && (
        <div className="precautions-box">
          <div className="precautions-title">
            <Compass size={16} />
            <span>Recommended Precautions</span>
          </div>
          <ul className="precautions-list">
            {recommendations.map((rec, i) => (
              <li key={i}>{rec}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Heuristic Disclaimer */}
      <div className="disclaimer-banner">
        <Info size={20} style={{ flexShrink: 0, marginTop: '2px' }} />
        <div>
          <strong>Heuristic Security Disclaimer:</strong> The QRShield score is an algorithmic
          risk indicator based strictly on static URL syntax, protocol conventions, and domain indicators.
          It does not execute page scripts, inspect backend servers, or guarantee that any low-risk URL
          is harmless. Always exercise personal vigilance before submitting passwords or sensitive data.
        </div>
      </div>
    </div>
  );
}
