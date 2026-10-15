/**
 * QRShield Client-Side Offline Simulation Engine
 * Mirrors the Python backend rules for demo and offline unit testing purposes.
 * Results clearly flag is_mock: true.
 * Parity with backend/rules.py is enforced by verify_parity.js.
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

// Words phishing domains glue onto a brand name (e.g. 'paypalsecure', 'appleid')
const SECURITY_ACTION_KEYWORDS = new Set([
  'login', 'signin', 'verify', 'secure', 'account', 'update',
  'banking', 'password', 'recover', 'authenticate', 'wallet', 'support',
  'id', 'online', 'service', 'help', 'official'
]);

// Credential-harvesting words that turn brand impersonation into a phishing lure
const LURE_KEYWORDS = new Set([
  'login', 'signin', 'verify', 'secure', 'account', 'update',
  'banking', 'password', 'recover', 'authenticate', 'wallet', 'support'
]);

// TLD-like labels used when a brand's full domain is embedded in front of another domain
const EMBEDDED_DOMAIN_TLDS = new Set(['com', 'net', 'org', 'co', 'io', 'in', 'uk', 'us', 'gov', 'edu', 'info', 'biz']);

// Two-part public suffixes, so 'amazon.co.uk' is read as name 'amazon' + suffix 'co.uk'
const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.in', 'org.in', 'ac.in', 'gov.in', 'net.in',
  'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'com.br', 'com.cn', 'com.mx',
  'co.za', 'com.sg', 'com.hk', 'co.kr', 'com.tr'
]);

// Real brand-owned domains that look like 'brand + word' phishing domains
const BRAND_OWNED_DOMAINS = new Set([
  'microsoftonline.com', 'google-analytics.com', 'paypal-community.com', 'amazon-adsystem.com'
]);

// Ordinary words that are one letter away from a brand (e.g. 'finance' vs 'binance')
const TYPO_EXCEPTIONS = new Set(['finance']);

// Characters that look like Latin letters: digits, Cyrillic and Greek look-alikes
const LOOKALIKE_CHARS = {
  '0': 'o', '1': 'l', 'i': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b',
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
  'і': 'l', 'ј': 'j', 'ԁ': 'd', 'ѕ': 's', 'һ': 'h', 'ӏ': 'l', 'к': 'k', 'м': 'm', 'т': 't',
  'ο': 'o', 'α': 'a', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'ι': 'l', 'κ': 'k', 'ε': 'e', 'υ': 'u', 'μ': 'm'
};

// Minimum score when any CRITICAL finding is present (start of the High band)
const CRITICAL_SCORE_FLOOR = 70;

// How each brand is written in findings ('paypal' -> 'PayPal', 'wellsfargo' -> 'Wells Fargo')
const BRAND_DISPLAY_NAMES = {
  paypal: 'PayPal', apple: 'Apple', microsoft: 'Microsoft', google: 'Google',
  amazon: 'Amazon', netflix: 'Netflix', facebook: 'Facebook', instagram: 'Instagram',
  chase: 'Chase', wellsfargo: 'Wells Fargo', bankofamerica: 'Bank of America',
  citibank: 'Citibank', binance: 'Binance', coinbase: 'Coinbase', metamask: 'MetaMask',
  whatsapp: 'WhatsApp', telegram: 'Telegram'
};
const displayName = (brand) => BRAND_DISPLAY_NAMES[brand] || brand;

/** RFC 3492 punycode decoder (browsers have no built-in one). */
function punycodeDecode(input) {
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  const digitOf = (cp) => {
    if (cp >= 0x30 && cp <= 0x39) return cp - 0x30 + 26;
    if (cp >= 0x41 && cp <= 0x5a) return cp - 0x41;
    if (cp >= 0x61 && cp <= 0x7a) return cp - 0x61;
    return base;
  };
  const adapt = (delta, numPoints, firstTime) => {
    let k = 0;
    delta = firstTime ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    for (; delta > ((base - tMin) * tMax) >> 1; k += base) {
      delta = Math.floor(delta / (base - tMin));
    }
    return Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
  };

  const output = [];
  const basic = Math.max(input.lastIndexOf('-'), 0);
  for (let j = 0; j < basic; j++) output.push(input.charCodeAt(j));

  let n = 128, bias = 72, i = 0;
  for (let index = basic > 0 ? basic + 1 : 0; index < input.length;) {
    const oldi = i;
    for (let w = 1, k = base; ; k += base) {
      if (index >= input.length) throw new Error('Invalid punycode');
      const digit = digitOf(input.charCodeAt(index++));
      if (digit >= base) throw new Error('Invalid punycode');
      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    const len = output.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    i %= len;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

/** Decodes a punycode ('xn--') label to the Unicode text the user actually sees. */
function decodeLabel(label) {
  if (!label.startsWith('xn--')) return label;
  try {
    return punycodeDecode(label.slice(4));
  } catch {
    return label;
  }
}

/** Splits host labels into [subdomain labels, registered name, public suffix]. */
function splitDomain(labels) {
  const suffixLen = labels.length >= 3 && MULTI_PART_SUFFIXES.has(labels.slice(-2).join('.')) ? 2 : 1;
  if (labels.length <= suffixLen) return [[], '', labels.join('.')];
  return [labels.slice(0, -suffixLen - 1), labels[labels.length - suffixLen - 1], labels.slice(-suffixLen).join('.')];
}

/** Reduces text to plain letters so look-alikes compare equal ('paypa1' -> 'paypal'). */
function skeleton(text) {
  return [...text.normalize('NFKD').replace(/\p{M}/gu, '')]
    .map(c => LOOKALIKE_CHARS[c] ?? c)
    .join('')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w');
}

/** True when a and b differ by exactly one insertion, deletion, substitution or adjacent swap. */
function isOneEditAway(a, b) {
  if (a === b || Math.abs(a.length - b.length) > 1) return false;
  if (a.length === b.length) {
    const diffs = [];
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) diffs.push(i);
    if (diffs.length === 1) return true;
    return diffs.length === 2 && diffs[1] === diffs[0] + 1 &&
      a[diffs[0]] === b[diffs[1]] && a[diffs[1]] === b[diffs[0]];
  }
  const [shorter, longer] = a.length < b.length ? [a, b] : [b, a];
  for (let i = 0; i < longer.length; i++) {
    if (longer.slice(0, i) + longer.slice(i + 1) === shorter) return true;
  }
  return false;
}

/** True when Latin letters are mixed with Cyrillic or Greek ones in the same label. */
function hasMixedScript(text) {
  return /\p{Script=Latin}/u.test(text) && /[\p{Script=Cyrillic}\p{Script=Greek}]/u.test(text);
}

/** True when a word is a lure keyword, or a brand glued to one ('paypalsecure'). */
function hasLureWord(words) {
  return words.some(word =>
    LURE_KEYWORDS.has(word) ||
    TARGETED_BRAND_KEYWORDS.some(brand =>
      (word.startsWith(brand) && LURE_KEYWORDS.has(word.slice(brand.length))) ||
      (word.endsWith(brand) && LURE_KEYWORDS.has(word.slice(0, -brand.length)))
    )
  );
}

/**
 * Returns the first brand that appears as a whole word, or glued to a security
 * keyword ('paypalsecure', 'appleid'). 'pineapple' and 'purchase' do not match.
 */
function findBrandWord(words) {
  for (const word of words) {
    for (const brand of TARGETED_BRAND_KEYWORDS) {
      if (word === brand) return brand;
      if (word.startsWith(brand) && SECURITY_ACTION_KEYWORDS.has(word.slice(brand.length))) return brand;
      if (word.endsWith(brand) && SECURITY_ACTION_KEYWORDS.has(word.slice(0, -brand.length))) return brand;
    }
  }
  return null;
}

/** The authority ('user@host:port') exactly as written, with '\' read as '/' like a browser. */
function getRawAuthority(rawUrl) {
  const cut = rawUrl.search(/[?#]/);
  const head = (cut === -1 ? rawUrl : rawUrl.slice(0, cut)).replace(/\\/g, '/');
  const match = head.match(/^[a-z][a-z0-9+.-]*:\/\/([^/]*)/i);
  return match ? match[1] : '';
}

function safeDecode(text) {
  try {
    return decodeURIComponent(text);
  } catch {
    return text;
  }
}

export function runClientMockAnalysis(rawUrl) {
  const urlObj = new URL(rawUrl);
  const scheme = urlObj.protocol.replace(':', '').toLowerCase();
  const hostname = urlObj.hostname.toLowerCase();
  const port = urlObj.port ? parseInt(urlObj.port, 10) : null;
  const originalUrl = rawUrl;
  const findings = [];

  const rawAuthority = getRawAuthority(originalUrl);
  const rawHostPart = rawAuthority.slice(rawAuthority.lastIndexOf('@') + 1);
  const rawHostname = rawHostPart.startsWith('[') ? '' : rawHostPart.split(':')[0].toLowerCase();

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
  if (rawAuthority.includes('@')) {
    const userinfo = safeDecode(rawAuthority.slice(0, rawAuthority.lastIndexOf('@')).toLowerCase());
    const userPart = userinfo.split(':')[0];
    const looksLikeDomain = /^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\.?$/.test(userPart);
    const namesBrand = findBrandWord(userPart.split(/[^a-z0-9]+/).filter(Boolean)) !== null;

    if (looksLikeDomain || namesBrand) {
      findings.push({
        rule_id: 'SEC-CRED-002',
        title: "Disguised Destination ('@' Trick)",
        severity: 'CRITICAL',
        score_impact: 35,
        description: `The text before '@' ('${userPart}') looks like a website address, but browsers treat it as a username and actually open '${hostname}'.`,
        recommendation: "Do not open this URL. The real destination is the part after the '@'."
      });
    } else {
      findings.push({
        rule_id: 'SEC-CRED-002',
        title: 'Embedded Authentication Credentials',
        severity: 'HIGH',
        score_impact: 35,
        description: "The URL embeds credentials or deceptive '@' delimiter syntax in the host portion. Attackers frequently use this technique to deceive users regarding the actual host being contacted.",
        recommendation: 'Do not open this URL. It is a recognized phishing obfuscation tactic.'
      });
    }
  }

  // 3. IP Hostname (new URL() has already decoded disguised IPv4 forms)
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

    // 3b. IP written in a disguised numeric form ('3232235876', '0xC0A80164', '127.1')
    if (!hostname.startsWith('[') && rawHostname && rawHostname.replace(/\.+$/, '') !== hostname) {
      findings.push({
        rule_id: 'SEC-IPOBF-014',
        title: 'Disguised IP Address',
        severity: 'CRITICAL',
        score_impact: 25,
        description: `The address is written in an obfuscated numeric form ('${rawHostname}') that browsers silently decode to ${hostname}.`,
        recommendation: 'Do not open this URL. The address was deliberately disguised.'
      });
    }
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
      score_impact: 30,
      description: `The hostname '${hostname}' is a URL shortening service. Shorteners mask the ultimate destination and are frequently used in QR codes to conceal deceptive links.`,
      recommendation: 'Use a preview or link expansion service to inspect the target destination before browsing.'
    });
  }

  // Domain checks
  if (!isIp && hostname) {
    const labels = hostname.split('.').filter(Boolean);
    const [subdomainLabels, registeredName, publicSuffix] = splitDomain(labels);
    const registeredDomain = registeredName ? `${registeredName}.${publicSuffix}` : hostname;
    const tld = labels[labels.length - 1];
    const decodedLabels = labels.map(decodeLabel);

    if (subdomainLabels.length >= 3) {
      findings.push({
        rule_id: 'SEC-SUBDOM-006',
        title: 'Excessive Subdomain Depth',
        severity: 'MEDIUM',
        score_impact: 15,
        description: `The hostname has ${subdomainLabels.length} subdomain levels in front of the registered domain '${registeredDomain}'. Excessive subdomains are frequently engineered to confuse users and obscure the true registration domain.`,
        recommendation: `Verify the registered domain ('${registeredDomain}') carefully before trusting this site.`
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

    // Counted on decoded labels so the 'xn--' punycode prefix is not counted
    const hyphens = decodedLabels.reduce((acc, lbl) => acc + (lbl.match(/-/g) || []).length, 0);
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

    // A brand's own site: the registered name IS the brand, on a normal TLD
    const isOfficialBrandDomain =
      (TARGETED_BRAND_KEYWORDS.includes(registeredName) && !HIGH_ABUSE_TLDS.has(tld)) ||
      BRAND_OWNED_DOMAINS.has(registeredDomain);

    const words = labels.flatMap(lbl => lbl.split('-')).filter(Boolean);
    const brand = findBrandWord(words);
    if (brand && !isOfficialBrandDomain) {
      const pathWords = urlObj.pathname.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
      const hasLure = hasLureWord(words) || hasLureWord(pathWords);
      // 'paypal.com.evil.com': the brand's full domain sits in front of the real one
      const embedsBrandDomain = subdomainLabels.some(
        (lbl, i) => lbl === brand && i + 1 < subdomainLabels.length && EMBEDDED_DOMAIN_TLDS.has(subdomainLabels[i + 1])
      );

      if (hasLure || embedsBrandDomain) {
        const reason = hasLure
          ? 'also uses login/verification wording to lure users into entering credentials'
          : `places '${brand}' as a fake domain in front of the real one`;
        findings.push({
          rule_id: 'SEC-SPOOF-010',
          title: `Brand Impersonation with Phishing Lure (${displayName(brand)})`,
          severity: 'CRITICAL',
          score_impact: 30,
          description: `The brand name '${brand}' appears in '${hostname}', but the registered domain '${registeredDomain}' is not an official ${displayName(brand)} domain, and the link ${reason}. This is the classic phishing pattern.`,
          recommendation: 'Do not provide credentials. Navigate directly to the official website by typing the official address in your browser.'
        });
      } else {
        findings.push({
          rule_id: 'SEC-SPOOF-010',
          title: `Potential Brand Impersonation (${displayName(brand)})`,
          severity: 'HIGH',
          score_impact: 30,
          description: `The brand name '${brand}' appears in '${hostname}', but the registered domain '${registeredDomain}' is not an official ${displayName(brand)} domain.`,
          recommendation: 'Do not provide credentials. Navigate directly to the official website by typing the official address in your browser.'
        });
      }
    }

    // Look-alike / typosquatted brand name (checked on the registered name and its words)
    if (registeredName && !isOfficialBrandDomain) {
      const visibleName = decodeLabel(registeredName);
      const candidates = [visibleName, ...visibleName.split('-').filter(w => w && w !== visibleName)];

      let lookalike = null;
      for (const candidate of candidates) {
        const b = TARGETED_BRAND_KEYWORDS.find(br => candidate !== br && skeleton(candidate) === skeleton(br));
        if (b) { lookalike = [candidate, b]; break; }
      }

      let typo = null;
      if (!lookalike) {
        for (const candidate of candidates) {
          if (TYPO_EXCEPTIONS.has(candidate)) continue;
          const b = TARGETED_BRAND_KEYWORDS.find(br => br.length >= 6 && isOneEditAway(candidate, br));
          if (b) { typo = [candidate, b]; break; }
        }
      }

      if (lookalike) {
        findings.push({
          rule_id: 'SEC-TYPO-015',
          title: `Look-alike Brand Name (${displayName(lookalike[1])})`,
          severity: 'CRITICAL',
          score_impact: 35,
          description: `'${lookalike[0]}' uses look-alike characters (such as 1 for l, 0 for o, or Cyrillic letters) to imitate '${lookalike[1]}'. The registered domain '${registeredDomain}' is not owned by ${displayName(lookalike[1])}.`,
          recommendation: `Do not open this URL. Type the official ${displayName(lookalike[1])} address yourself.`
        });
      } else if (typo) {
        findings.push({
          rule_id: 'SEC-TYPO-015',
          title: `Possible Typosquatted Brand (${displayName(typo[1])})`,
          severity: 'HIGH',
          score_impact: 30,
          description: `'${typo[0]}' is one letter away from the brand '${typo[1]}'. Attackers register misspelled brand domains to catch users who misread or mistype addresses.`,
          recommendation: `Check the spelling carefully. The official ${displayName(typo[1])} site is not '${registeredDomain}'.`
        });
      }
    }

    // Internationalized (punycode) domain
    const idnLabels = labels.filter(lbl => lbl.startsWith('xn--'));
    if (idnLabels.length) {
      const mixed = idnLabels.some(lbl => hasMixedScript(decodeLabel(lbl)));
      let description = `The domain uses international characters and displays as '${decodedLabels.join('.')}' (encoded as '${hostname}'). Look-alike letters from other alphabets can make a fake domain appear identical to a real one.`;
      if (mixed) {
        description += ' It mixes Latin letters with Cyrillic or Greek letters in the same label, which legitimate domains do not do.';
      }
      findings.push({
        rule_id: 'SEC-IDN-016',
        title: mixed ? 'Mixed-Alphabet Domain' : 'Internationalized Domain Name',
        severity: mixed ? 'HIGH' : 'MEDIUM',
        score_impact: mixed ? 30 : 15,
        description,
        recommendation: 'Compare each character of the address with the official site before trusting it.'
      });
    }
  }

  // Match the backend: only the path and query are inspected (not the host or #fragment)
  if (/(?:url|redirect|next|dest|target|link)=(?:https?%3A%2F%2F|https?:\/\/)/i.test(urlObj.pathname + urlObj.search)) {
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

  // Backslash before the query/fragment (new URL() has already converted it to '/')
  if (originalUrl.split(/[?#]/)[0].includes('\\')) {
    findings.push({
      rule_id: 'SEC-BSLASH-013',
      title: 'Backslash in URL Address',
      severity: 'CRITICAL',
      score_impact: 30,
      description: `The URL contains a backslash (\\) before its path or query. Browsers treat it as a forward slash, so the link really goes to '${hostname}' even if the text suggests a different site.`,
      recommendation: 'Do not open this URL. Legitimate links never need a backslash in the address.'
    });
  }

  // Compute score
  let rawScore = findings.reduce((acc, f) => acc + f.score_impact, 0);
  if (findings.length >= 3) {
    rawScore += 10;
  }
  let riskScore = Math.max(0, Math.min(100, rawScore));
  // CRITICAL findings are tricks with no legitimate use: always at least High risk
  if (findings.some(f => f.severity === 'CRITICAL')) {
    riskScore = Math.max(riskScore, CRITICAL_SCORE_FLOOR);
  }
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
    engine_version: '1.3.0 (Client Offline Simulation)'
  };
}
