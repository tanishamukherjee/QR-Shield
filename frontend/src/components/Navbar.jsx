import React from 'react';
import { Shield, Cloud, Terminal } from 'lucide-react';

const STATUS_BADGES = {
  checking: {
    className: 'badge-status-checking',
    label: 'Checking Backend…',
    title: 'Contacting the Python threat engine'
  },
  live: {
    className: 'badge-status-live',
    label: 'Backend Active',
    title: 'Connected to Python Threat Engine'
  },
  offline: {
    className: 'badge-status-mock',
    label: 'Backend Unreachable · Simulation',
    title: 'The backend did not respond; scans use the local offline simulation'
  },
  'forced-offline': {
    className: 'badge-status-mock',
    label: 'Offline Simulation',
    title: 'Offline simulation mode is configured (VITE_ENABLE_OFFLINE_MOCK or no VITE_API_BASE_URL)'
  }
};

export default function Navbar({ backendStatus }) {
  const status = STATUS_BADGES[backendStatus] || STATUS_BADGES.checking;

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

        <span className={`badge ${status.className}`} title={status.title}>
          <span className="status-dot"></span>
          {status.label}
        </span>
      </div>
    </header>
  );
}
