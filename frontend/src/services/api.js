import { runClientMockAnalysis } from './mockAnalyzer';

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').trim();
const FORCE_OFFLINE_MOCK = import.meta.env.VITE_ENABLE_OFFLINE_MOCK === 'true';

/**
 * Checks whether the backend health route (GET /) answers.
 * Returns 'forced-offline' (simulation configured), 'live' or 'offline'.
 */
export async function checkBackendHealth() {
  if (FORCE_OFFLINE_MOCK || !API_BASE_URL) {
    return 'forced-offline';
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000); // allows for a Lambda cold start
    const response = await fetch(API_BASE_URL.replace(/\/+$/, '') + '/', { signal: controller.signal });
    clearTimeout(timeoutId);
    return response.ok ? 'live' : 'offline';
  } catch {
    return 'offline';
  }
}

/**
 * Sends a URL to the backend Lambda Function URL for threat analysis.
 * Automatically falls back to client-side simulation when offline or unconfigured,
 * ensuring clear visual indicators so mock is never mistaken for live AWS.
 */
export async function analyzeTargetUrl(url) {
  // If explicitly configured for offline simulation
  if (FORCE_OFFLINE_MOCK || !API_BASE_URL) {
    // Add realistic 400ms delay to simulate network latency
    await new Promise(r => setTimeout(r, 400));
    return runClientMockAnalysis(url);
  }

  const endpoint = API_BASE_URL.replace(/\/+$/, '') + '/';

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000); // 8s timeout

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    const data = await response.json().catch(() => null);

    if (!response.ok) {
      const errorMsg = (data && data.message) || `Server returned HTTP ${response.status}`;
      const httpError = new Error(errorMsg);
      httpError.backendReachable = true; // the backend answered, it just rejected the input
      throw httpError;
    }

    return {
      ...data,
      is_mock: false
    };
  } catch (error) {
    // If network error (backend server not started or CORS failure), fallback to client simulation with notification
    if (error.name === 'AbortError') {
      const timeoutError = new Error('Analysis timed out after 8 seconds. Please check backend connection.');
      timeoutError.backendReachable = false;
      throw timeoutError;
    }

    // If it's a fetch network error (e.g. Failed to fetch when local backend isn't running)
    if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
      console.warn('Backend endpoint unreachable at', endpoint, 'Falling back to offline client simulation.');
      const simulated = runClientMockAnalysis(url);
      simulated.is_fallback_simulation = true;
      return simulated;
    }

    // If backend gave a 400 validation error, bubble it up directly to the UI
    throw error;
  }
}
