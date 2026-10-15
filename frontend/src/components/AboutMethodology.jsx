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
            Requests arrive directly via a public HTTPS <strong>AWS Lambda Function URL</strong>, eliminating
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
            <span>16 Deterministic Rules Evaluated</span>
          </div>
          <div className="method-desc">
            <ul style={{ paddingLeft: '1.2rem', marginTop: '0.4rem', lineHeight: '1.6' }}>
              <li><strong>Protocol:</strong> Flags unencrypted plain HTTP (SEC-SCHEME-001).</li>
              <li><strong>Credentials:</strong> Detects embedded usernames/passwords and the disguised <code>real-site@evil-site</code> trick (SEC-CRED-002).</li>
              <li><strong>Raw IP:</strong> Identifies raw IPv4/IPv6 used in place of domain names (SEC-IP-003).</li>
              <li><strong>Ports:</strong> Flags non-standard ports like 8080, 8443, 3389, 21 (SEC-PORT-004).</li>
              <li><strong>Shorteners:</strong> Detects URL masking services like Bit.ly/TinyURL (SEC-SHORT-005).</li>
              <li><strong>Subdomains:</strong> Flags deep subdomain stuffing in front of the real domain (SEC-SUBDOM-006).</li>
              <li><strong>Hostname Length:</strong> Flags unusually long hostnames (SEC-LEN-007).</li>
              <li><strong>Hyphens:</strong> Flags hyphen-stuffed hostnames (SEC-HYPHEN-008).</li>
              <li><strong>TLD Reputation:</strong> Evaluates historically abused low-cost TLDs (SEC-TLD-009).</li>
              <li><strong>Brand Spoofing:</strong> Brand names on domains the brand does not own, escalated when paired with login lures (SEC-SPOOF-010).</li>
              <li><strong>Redirects:</strong> Detects chained URLs in redirect parameters (SEC-REDIR-011).</li>
              <li><strong>URL Length:</strong> Flags oversized URLs (SEC-URLLEN-012).</li>
              <li><strong>Backslash Trick:</strong> Detects <code>\</code> used to disguise the real host (SEC-BSLASH-013).</li>
              <li><strong>Disguised IP:</strong> Detects IPs written in decimal, hex or octal form (SEC-IPOBF-014).</li>
              <li><strong>Typosquatting:</strong> Detects look-alike and misspelled brand names like <code>paypa1</code> (SEC-TYPO-015).</li>
              <li><strong>International Characters:</strong> Flags punycode and mixed-alphabet look-alike domains (SEC-IDN-016).</li>
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
            Any <strong>CRITICAL</strong> finding (a deception trick with no legitimate use) always raises the result to High.
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
              <li><strong>Browser-Equivalent Parsing:</strong> Every URL is read exactly as a browser would read it, so tricks that hide the real host are analyzed against the true destination.</li>
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
