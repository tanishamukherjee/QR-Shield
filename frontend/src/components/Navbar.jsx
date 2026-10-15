import React from 'react';
import { Shield, Cloud, Terminal } from 'lucide-react';

export default function Navbar({ isMockMode }) {
  return (
    <header className="navbar">
      <div className="brand">
        <div className="brand-icon">
          <Shield size={24} strokeWidth={2.5} />
        </div>
        <div className="brand-text">
          <h1>QRShield</h1>
          <span>Cloud-Based Threat Detection</span>
        </div>
      </div>

      <div className="nav-badges">
        <span className="badge badge-aws" title="Architecture: AWS Lambda Serverless Function URL">
          <Cloud size={13} />
          AWS Serverless
        </span>

        {isMockMode ? (
          <span className="badge badge-status-mock" title="Operating in offline simulation fallback mode">
            <span className="status-dot"></span>
            Offline Simulation
          </span>
        ) : (
          <span className="badge badge-status-live" title="Connected to Python Threat Engine">
            <span className="status-dot"></span>
            Backend Active
          </span>
        )}
      </div>
    </header>
  );
}
