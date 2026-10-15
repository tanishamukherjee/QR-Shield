import React, { useState } from 'react';
import { Link, Copy, Check, ShieldAlert, Server } from 'lucide-react';

export default function DecodedUrlPanel({ url, hostname }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (e) {
      console.error('Failed to copy URL:', e);
    }
  };

  if (!url) return null;

  return (
    <div className="decoded-panel">
      <div className="decoded-header">
        <span className="decoded-label">
          <Link size={14} />
          Decoded Target Link
        </span>
        <span className="badge" style={{ background: 'rgba(56, 189, 248, 0.1)', color: '#38bdf8' }}>
          <Server size={12} />
          Host: {hostname || 'Unknown'}
        </span>
      </div>

      <div className="url-display-box">
        <span>{url}</span>
        <button
          type="button"
          className="btn-copy"
          onClick={handleCopy}
          title="Copy URL to clipboard"
        >
          {copied ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>

      <div className="security-notice">
        <ShieldAlert size={14} color="#f59e0b" />
        <span>
          Static Analysis Safe Zone: QRShield does not follow redirects or load remote web content.
        </span>
      </div>
    </div>
  );
}
