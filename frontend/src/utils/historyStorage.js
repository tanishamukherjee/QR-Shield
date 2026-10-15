const STORAGE_KEY = 'qrshield_scan_history_v1';
const MAX_HISTORY_ITEMS = 10;

/**
 * Sanitizes URL for history storage by stripping credentials and query tokens.
 */
function sanitizeUrlForStorage(url) {
  try {
    const u = new URL(url);
    const host = u.port ? `${u.hostname}:${u.port}` : u.hostname;
    let clean = `${u.protocol}//${host}${u.pathname}`;
    if (u.search) {
      clean += '?params=redacted';
    }
    return clean;
  } catch {
    return url.split('?')[0];
  }
}

/**
 * Loads recent scan history from localStorage.
 */
export function getScanHistory() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    console.error('Failed to parse scan history from localStorage:', e);
    return [];
  }
}

/**
 * Adds a new scan record to localStorage (bounded to MAX_HISTORY_ITEMS).
 */
export function saveScanToHistory(result) {
  try {
    const history = getScanHistory();
    const entry = {
      id: `${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
      timestamp: result.analyzed_at || new Date().toISOString(),
      displayUrl: sanitizeUrlForStorage(result.normalized_url || ''),
      hostname: result.hostname || 'unknown',
      risk_level: result.risk_level || 'Low',
      risk_score: result.risk_score || 0,
      findings_count: (result.findings || []).length,
      is_mock: !!result.is_mock
    };

    // Filter out duplicates of exact same hostname scanned within the last 10 seconds
    const updated = [entry, ...history.filter(h => h.displayUrl !== entry.displayUrl)].slice(0, MAX_HISTORY_ITEMS);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    return updated;
  } catch (e) {
    console.error('Failed to save scan to localStorage:', e);
    return [];
  }
}

/**
 * Clears all scan history records from localStorage.
 */
export function clearScanHistory() {
  try {
    localStorage.removeItem(STORAGE_KEY);
    return [];
  } catch (e) {
    console.error('Failed to clear scan history:', e);
    return [];
  }
}
