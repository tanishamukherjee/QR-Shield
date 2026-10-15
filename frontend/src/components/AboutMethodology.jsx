import React from 'react';
import { ShieldCheck, Cloud, Cpu, Lock, AlertTriangle, Layers, CheckCircle } from 'lucide-react';

export default function AboutMethodology() {
  return (
    <div className="card" style={{ marginTop: '2rem' }}>
      <div className="card-title">
        <Layers size={20} className="text-accent" />
        <h3>System Architecture & Threat Methodology</h3>
      </div>
      <p className="card-subtitle">
        QRShield combines zero-knowledge client-side QR image decoding with a stateless AWS Lambda security rule engine.
      </p>

      <div className="methodology-grid">
        {/* Architecture Card */}
        <div className="method-card">
          <div className="method-title">
            <Cloud size={18} />
            <span>AWS Serverless Core</span>
          </div>
          <div className="method-desc">
            The threat analysis engine runs entirely on <strong>AWS Lambda</strong> using Python 3.
            Requests arrive directly via an authenticated <strong>AWS Lambda Function URL</strong>, eliminating
            idle EC2 costs and load balancers. Execution logs are securely aggregated into <strong>Amazon CloudWatch</strong> with automated credential and token redaction.
          </div>
        </div>

        {/* Privacy by Design */}
        <div className="method-card">
          <div className="method-title">
            <Lock size={18} />
            <span>Client-Side Privacy</span>
          </div>
          <div className="method-desc">
            QR images are decoded locally inside the browser using HTML5 Canvas and <code>jsQR</code>.
            Image files are <strong>never uploaded to the cloud or stored on disks</strong>. Only the
            extracted URL payload is transmitted to the serverless analyzer.
          </div>
        </div>

        {/* Detection Rules */}
        <div className="method-card">
          <div className="method-title">
            <Cpu size={18} />
            <span>Deterministic Rules Evaluated</span>
          </div>
          <div className="method-desc">
            <ul style={{ paddingLeft: '1.2rem', marginTop: '0.4rem', lineHeight: '1.6' }}>
              <li><strong>Protocol:</strong> Flags unencrypted plain HTTP (SEC-SCHEME-001).</li>
              <li><strong>Credentials:</strong> Detects embedded usernames/passwords (SEC-CRED-002).</li>
              <li><strong>Raw IP:</strong> Identifies raw IPv4/IPv6 used in place of domain names (SEC-IP-003).</li>
              <li><strong>Ports:</strong> Flags non-standard ports like 8080, 8443, 3389, 21 (SEC-PORT-004).</li>
              <li><strong>Shorteners:</strong> Detects URL masking services like Bit.ly/TinyURL (SEC-SHORT-005).</li>
              <li><strong>Spoofing:</strong> Identifies brand typosquatting & subdomain stuffing (SEC-SPOOF-010).</li>
              <li><strong>TLD Reputation:</strong> Evaluates historically abused low-cost TLDs (SEC-TLD-009).</li>
            </ul>
          </div>
        </div>

        {/* Transparent Scoring */}
        <div className="method-card">
          <div className="method-title">
            <ShieldCheck size={18} />
            <span>Scoring & Thresholds</span>
          </div>
          <div className="method-desc">
            Risk scores range strictly from <strong>0 to 100</strong>. Each triggered rule contributes an additive
            impact weight. When three or more distinct indicators fire simultaneously, a compound penalty is applied.
            <div style={{ marginTop: '0.5rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <span className="badge badge-low">Low: 0 – 29</span>
              <span className="badge badge-medium">Medium: 30 – 69</span>
              <span className="badge badge-high">High: 70 – 100</span>
            </div>
          </div>
        </div>

        {/* Security Safeguards */}
        <div className="method-card" style={{ gridColumn: '1 / -1' }}>
          <div className="method-title" style={{ color: 'var(--accent-cyan)' }}>
            <Lock size={18} />
            <span>Core Application Security Safeguards</span>
          </div>
          <div className="method-desc">
            <ul style={{ paddingLeft: '1.2rem', marginTop: '0.4rem', lineHeight: '1.6' }}>
              <li><strong>Zero Outbound Probing (SSRF Immunity):</strong> The backend analyzes URL syntax without fetching external content, preventing Server-Side Request Forgery and attacker tracking.</li>
              <li><strong>CloudWatch Telemetry Redaction:</strong> Sensitive query parameters (e.g. <code>?token=...</code>) and credentials are automatically scrubbed before writing to cloud logs.</li>
              <li><strong>Zero Auto-Navigation:</strong> Decoded links are rendered strictly in read-only monospace panels with a copy button. Automatic execution is strictly prohibited.</li>
              <li><strong>Input Validation & Strict Limits:</strong> Enforces a 2,048-character limit and rejects non-HTTP(S) schemes (<code>javascript:</code>, <code>file:</code>, <code>tel:</code>).</li>
            </ul>
          </div>
        </div>

        {/* Project Limitations */}
        <div className="method-card" style={{ gridColumn: '1 / -1' }}>
          <div className="method-title" style={{ color: '#fbbf24' }}>
            <AlertTriangle size={18} />
            <span>Prototype Scope & Safety Guarantees</span>
          </div>
          <div className="method-desc">
            QRShield is an academic security prototype built for college demonstration purposes.
            It performs <strong>static, non-intrusive URL analysis</strong> and does not actively crawl, execute JavaScript, or query paid threat feeds.
            A "Low Risk" result signifies that no known suspicious structural flags were identified, but does not provide an absolute guarantee of safety.
          </div>
        </div>
      </div>
    </div>
  );
}
