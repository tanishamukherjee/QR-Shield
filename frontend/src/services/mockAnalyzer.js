/**
 * QRShield Client-Side Offline Simulation Engine
 * Mirrors the Python backend rules for demo and offline unit testing purposes.
 * Results clearly flag is_mock: true.
 */

const KNOWN_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly',
  'cutt.ly', 'rb.gy', 'goo.gl', 'rebrand.ly', 'tiny.cc', 'shorte.st',
  'v.gd', 'qr.ae', 'trib.al', 'bl.ink', 'lnkd.in', 's.id'
]);

const HIGH_ABUSE_TLDS = new Set([
  'top', 'xyz', 'work', 'click', 'gq', 'cf', 'tk', 'ml', 'ga',
  'buzz', 'fit', 'surf', 'loan', 'men', 'tokyo', 'casa'
]);

const TARGETED_BRAND_KEYWORDS = [
  'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix',
  'facebook', 'instagram', 'chase', 'wellsfargo', 'bankofamerica',
  'citibank', 'binance', 'coinbase', 'metamask', 'whatsapp', 'telegram'
];

export function runClientMockAnalysis(rawUrl) {
  const urlObj = new URL(rawUrl);
  const scheme = urlObj.protocol.replace(':', '').toLowerCase();
  const hostname = urlObj.hostname.toLowerCase();
  const port = urlObj.port ? parseInt(urlObj.port, 10) : null;
  const originalUrl = rawUrl;
  const findings = [];

  // 1. HTTP Scheme
  if (scheme === 'http') {
    findings.push({
      rule_id: 'SEC-SCHEME-001',
      title: 'Unencrypted HTTP Scheme',
      severity: 'MEDIUM',
      score_impact: 20,
      description: 'The URL uses plain HTTP instead of HTTPS. Traffic to this destination is transmitted unencrypted and vulnerable to eavesdropping or man-in-the-middle interception.',
      recommendation: 'Do not enter passwords, personal details, or financial data on unencrypted HTTP pages.'
    });
  }

  // 2. Embedded credentials
  if (urlObj.username || urlObj.password || urlObj.host.includes('@')) {
    findings.push({
      rule_id: 'SEC-CRED-002',
      title: 'Embedded Authentication Credentials',
      severity: 'HIGH',
      score_impact: 35,
      description: "The URL embeds credentials or deceptive '@' delimiter syntax in the host portion. Attackers frequently use this technique to deceive users regarding the actual host being contacted.",
      recommendation: 'Do not open this URL. It is a recognized phishing obfuscation tactic.'
    });
  }

  // 3. IP Hostname
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.startsWith('[');
  if (isIp) {
    findings.push({
      rule_id: 'SEC-IP-003',
      title: 'IP Address Used as Hostname',
      severity: 'HIGH',
      score_impact: 30,
      description: `The URL connects directly to an IP address (${hostname}) rather than a registered domain name.`,
      recommendation: 'Legitimate public websites rarely publish bare IP addresses in QR codes. Treat this destination with extreme caution.'
    });
  }

  // 4. Unusual Port
  if (port) {
    const standardPorts = scheme === 'http' ? [80] : [443];
    if (!standardPorts.includes(port)) {
      const isHigh = [21, 22, 23, 25, 3389, 4444, 6667].includes(port);
      findings.push({
        rule_id: 'SEC-PORT-004',
        title: `Non-Standard Port (${port})`,
        severity: isHigh ? 'HIGH' : 'MEDIUM',
        score_impact: isHigh ? 25 : 15,
        description: `The URL specifies custom port ${port} instead of the standard web ports (80/443). Attackers may use custom ports to bypass network filters.`,
        recommendation: 'Verify whether the service operator legitimately expects traffic on this non-standard port.'
      });
    }
  }

  // 5. URL Shorteners
  if (KNOWN_SHORTENERS.has(hostname)) {
    findings.push({
      rule_id: 'SEC-SHORT-005',
      title: 'Known URL Shortening Service',
      severity: 'MEDIUM',
      score_impact: 20,
      description: `The hostname '${hostname}' is a URL shortening service. Shorteners mask the ultimate destination and are frequently used in QR codes to conceal deceptive links.`,
      recommendation: 'Use a preview or link expansion service to inspect the target destination before browsing.'
    });
  }

  // Domain checks
  if (!isIp && hostname) {
    const labels = hostname.split('.').filter(Boolean);
    if (labels.length >= 5) {
      findings.push({
        rule_id: 'SEC-SUBDOM-006',
        title: 'Excessive Subdomain Depth',
        severity: 'MEDIUM',
        score_impact: 15,
        description: `The domain possesses ${labels.length} hierarchical labels. Excessive subdomains are frequently engineered to confuse users and obscure the true registration domain.`,
        recommendation: 'Verify the effective root domain (the final two labels) carefully before trusting this site.'
      });
    }

    if (hostname.length > 45) {
      findings.push({
        rule_id: 'SEC-LEN-007',
        title: 'Unusually Long Hostname',
        severity: 'LOW',
        score_impact: 10,
        description: `The hostname length (${hostname.length} characters) is significantly longer than typical web services.`,
        recommendation: 'Inspect the root domain for legitimacy.'
      });
    }

    const hyphens = (hostname.match(/-/g) || []).length;
    if (hyphens >= 3) {
      findings.push({
        rule_id: 'SEC-HYPHEN-008',
        title: 'Excessive Hyphens in Hostname',
        severity: 'MEDIUM',
        score_impact: 15,
        description: `The hostname contains ${hyphens} hyphens. Phishing kits commonly use hyphenated keywords to mimic authentic domains.`,
        recommendation: 'Confirm whether the authentic brand operates under this hyphenated domain.'
      });
    }

    const tld = labels[labels.length - 1];
    if (HIGH_ABUSE_TLDS.has(tld)) {
      findings.push({
        rule_id: 'SEC-TLD-009',
        title: `High-Risk Top-Level Domain (.${tld})`,
        severity: 'LOW',
        score_impact: 10,
        description: `The domain uses the '.${tld}' top-level domain, which has historically shown elevated rates of spam and abuse.`,
        recommendation: 'Exercise vigilance when visiting domains under low-reputation generic TLDs.'
      });
    }

    const regDomain = labels.length >= 2 ? labels.slice(-2).join('.') : hostname;
    const subDomain = labels.length > 2 ? labels.slice(0, -2).join('.') : '';
    for (const brand of TARGETED_BRAND_KEYWORDS) {
      if (subDomain.includes(brand) || (hostname.includes(brand) && !regDomain.startsWith(brand))) {
        findings.push({
          rule_id: 'SEC-SPOOF-010',
          title: `Potential Brand Impersonation (${brand.charAt(0).toUpperCase() + brand.slice(1)})`,
          severity: 'HIGH',
          score_impact: 30,
          description: `The recognized brand name '${brand}' appears in the subdomain or prefix of a domain registered to an unrelated entity ('${regDomain}').`,
          recommendation: 'Do not provide credentials. Navigate directly to the official website by typing the official address in your browser.'
        });
        break;
      }
    }
  }

  if (/(?:url|redirect|next|dest|target|link)=(?:https?%3A%2F%2F|https?:\/\/)/i.test(originalUrl)) {
    findings.push({
      rule_id: 'SEC-REDIR-011',
      title: 'Potential Open Redirect / Chained URL',
      severity: 'MEDIUM',
      score_impact: 15,
      description: 'The URL query parameters contain an embedded secondary web address. This pattern can be exploited as an open redirect.',
      recommendation: 'Ensure you verify where the redirect finally leads before authenticating.'
    });
  }

  if (originalUrl.length > 250) {
    findings.push({
      rule_id: 'SEC-URLLEN-012',
      title: 'Unusually Long URL',
      severity: 'LOW',
      score_impact: 10,
      description: `The full URL length (${originalUrl.length} characters) is unusually large.`,
      recommendation: 'Inspect query parameters for suspicious payload injections.'
    });
  }

  // Compute score
  let rawScore = findings.reduce((acc, f) => acc + f.score_impact, 0);
  if (findings.length >= 3) {
    rawScore += 10;
  }
  const riskScore = Math.max(0, Math.min(100, rawScore));
  const riskLevel = riskScore < 30 ? 'Low' : riskScore < 70 ? 'Medium' : 'High';

  let summary = '';
  if (findings.length === 0) {
    summary = `No suspicious structural indicators detected for '${hostname}'. The URL conforms to standard HTTPS conventions. However, static analysis cannot verify real-time backend behavior.`;
  } else if (riskLevel === 'High') {
    summary = `HIGH RISK: Detected ${findings.length} indicator(s) suggesting deception or abnormal configuration on '${hostname}'. We strongly advise against visiting this destination.`;
  } else if (riskLevel === 'Medium') {
    summary = `MEDIUM RISK: Detected ${findings.length} indicator(s) worthy of caution on '${hostname}'. Inspect findings before browsing.`;
  } else {
    summary = `LOW RISK: Detected ${findings.length} minor indicator(s) on '${hostname}'. Review findings prior to interaction.`;
  }

  const recommendations = Array.from(new Set(findings.map(f => f.recommendation)));
  recommendations.push("Verify the organization's authentic domain independently before entering credentials.");

  return {
    status: 'success',
    is_mock: true,
    risk_score: riskScore,
    risk_level: riskLevel,
    normalized_url: originalUrl,
    hostname,
    scheme,
    port,
    findings,
    summary,
    recommendations,
    analyzed_at: new Date().toISOString(),
    engine_version: '1.0.0 (Client Offline Simulation)'
  };
}
