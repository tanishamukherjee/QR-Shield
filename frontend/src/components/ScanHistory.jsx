import React from 'react';
import { History, Trash2, Eye, ShieldCheck, AlertTriangle, AlertOctagon } from 'lucide-react';

export default function ScanHistory({ history, onClearHistory, onSelectHistoryItem }) {
  if (!history || history.length === 0) {
    return (
      <div className="card">
        <div className="card-title">
          <History size={18} className="text-accent" />
          <h3>Recent Scan History</h3>
        </div>
        <div className="empty-history">
          No scans recorded yet. Upload a QR code or submit a URL to populate your recent inspection history.
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="history-header">
        <div className="card-title" style={{ margin: 0 }}>
          <History size={18} className="text-accent" />
          <h3>Recent Scans ({history.length})</h3>
        </div>
        <button
          type="button"
          className="btn-secondary"
          onClick={onClearHistory}
          title="Clear all stored scan history"
        >
          <Trash2 size={14} />
          Clear History
        </button>
      </div>

      <div className="history-list">
        {history.map((item) => {
          const badgeClass =
            item.risk_level === 'High' ? 'badge-high' : item.risk_level === 'Medium' ? 'badge-medium' : 'badge-low';

          const RiskIcon =
            item.risk_level === 'High' ? AlertOctagon : item.risk_level === 'Medium' ? AlertTriangle : ShieldCheck;

          const dateStr = item.timestamp
            ? new Date(item.timestamp).toLocaleString(undefined, {
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
              })
            : 'Recent';

          return (
            <div key={item.id} className="history-item">
              <div className="history-meta">
                <span className="history-url">{item.displayUrl}</span>
                <span className="history-time">
                  {item.hostname} · {dateStr} · {item.findings_count} indicator{item.findings_count !== 1 ? 's' : ''}
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <span className={`risk-level-badge ${badgeClass}`} style={{ fontSize: '0.75rem' }}>
                  <RiskIcon size={12} />
                  {item.risk_level} ({item.risk_score})
                </span>

                <button
                  type="button"
                  className="chip-btn"
                  onClick={() => onSelectHistoryItem(item)}
                  disabled={!item.result}
                  title={item.result ? 'View the saved analysis for this link' : 'Saved by an older version; details are not available'}
                >
                  <Eye size={13} />
                  View Result
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
