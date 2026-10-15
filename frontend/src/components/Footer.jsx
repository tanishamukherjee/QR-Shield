import React from 'react';
import { Shield, ExternalLink, Award } from 'lucide-react';

export default function Footer() {
  return (
    <footer className="footer">
      <div className="footer-content">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
          <Shield size={16} color="#00f2fe" />
          <span>QRShield — Cloud-Based QR Code Threat Detection System</span>
        </div>
        <div>
          College Project Demonstration · Submission Due: 25 October 2026
        </div>
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          Powered by AWS Lambda Serverless & React. Built in accordance with principle of least privilege and zero server idle costs.
        </div>
      </div>
    </footer>
  );
}
