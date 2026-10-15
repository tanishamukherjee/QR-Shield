import React, { useState, useEffect, useRef } from 'react';
import Navbar from './components/Navbar';
import Scanner from './components/Scanner';
import DecodedUrlPanel from './components/DecodedUrlPanel';
import AnalysisResults from './components/AnalysisResults';
import ScanHistory from './components/ScanHistory';
import AboutMethodology from './components/AboutMethodology';
import Footer from './components/Footer';

import { analyzeTargetUrl, checkBackendHealth } from './services/api';
import { getScanHistory, saveScanToHistory, clearScanHistory } from './utils/historyStorage';

import { QrCode, History, Layers, ShieldCheck, Radar } from 'lucide-react';
import './App.css';

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [extractedUrl, setExtractedUrl] = useState('');
  const [extractedHostname, setExtractedHostname] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [history, setHistory] = useState([]);
  // 'checking' | 'live' | 'offline' (backend unreachable) | 'forced-offline' (simulation configured)
  const [backendStatus, setBackendStatus] = useState('checking');

  const resultsRef = useRef(null);

  // Load history from localStorage on initial render
  useEffect(() => {
    setHistory(getScanHistory());
  }, []);

  // Check the backend health route once on load. A scan that finishes first wins.
  useEffect(() => {
    let cancelled = false;
    checkBackendHealth().then((status) => {
      if (!cancelled) {
        setBackendStatus(prev => (prev === 'checking' ? status : prev));
      }
    });
    return () => { cancelled = true; };
  }, []);

  // Auto-scroll to loading box when analysis starts
  useEffect(() => {
    if (isLoading && resultsRef.current) {
      const timer = setTimeout(() => {
        resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 50);
      return () => clearTimeout(timer);
    }
  }, [isLoading]);

  // Auto-scroll to results when analysis completes so user doesn't have to scroll
  useEffect(() => {
    if (scanResult && resultsRef.current) {
      const timer = setTimeout(() => {
        resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 80);
      return () => clearTimeout(timer);
    }
  }, [scanResult]);

  const handleUrlExtracted = async (url, source, errorMsg) => {
    if (errorMsg) {
      setError(errorMsg);
      setExtractedUrl('');
      setScanResult(null);
      return;
    }

    if (!url) return;

    setError('');
    setExtractedUrl(url);

    try {
      const parsed = new URL(url);
      setExtractedHostname(parsed.hostname);
    } catch {
      setExtractedHostname('');
    }

    // Trigger analysis
    await performAnalysis(url);
  };

  const performAnalysis = async (url) => {
    setIsLoading(true);
    setError('');

    try {
      const result = await analyzeTargetUrl(url);
      setScanResult(result);

      // Every result tells us whether the live backend answered
      if (result.is_mock) {
        setBackendStatus(prev => (prev === 'forced-offline' ? prev : 'offline'));
      } else {
        setBackendStatus('live');
      }

      // Persist to local storage
      const updatedHistory = saveScanToHistory(result);
      setHistory(updatedHistory);
    } catch (err) {
      setError(err.message || 'Failed to analyze URL.');
      setScanResult(null);
      if (err.backendReachable === true) {
        setBackendStatus('live');
      } else if (err.backendReachable === false) {
        setBackendStatus('offline');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearHistory = () => {
    if (window.confirm('Are you sure you want to clear your recent scan history?')) {
      const emptied = clearScanHistory();
      setHistory(emptied);
    }
  };

  // Shows the saved result. The stored URL is sanitized, so rescanning it would
  // analyze a different link and give a different score.
  const handleSelectHistoryItem = (item) => {
    if (!item.result) return;
    setActiveTab('scanner');
    setError('');
    setExtractedUrl(item.displayUrl);
    setExtractedHostname(item.hostname);
    setScanResult({ ...item.result, from_history: true });
  };

  return (
    <div className="app-container">
      <Navbar backendStatus={backendStatus} />

      <main className="main-content">
        {/* Hero Branding */}
        <section className="hero">
          <div className="hero-pill">
            <ShieldCheck size={14} />
            <span>Zero-Trust QR Code Security</span>
          </div>
          <h2>
            Detect Malicious Links Before <span>You Click</span>
          </h2>
          <p>
            Client-side QR code decoding paired with a deterministic AWS serverless heuristic engine.
            Analyzes obfuscation, brand spoofing, open redirects, and suspicious domain patterns.
          </p>
        </section>

        {/* Tab Navigation */}
        <nav className="tab-nav">
          <button
            type="button"
            className={`tab-btn ${activeTab === 'scanner' ? 'active' : ''}`}
            onClick={() => setActiveTab('scanner')}
          >
            <QrCode size={16} />
            <span>Scanner</span>
          </button>
          <button
            type="button"
            className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => setActiveTab('history')}
          >
            <History size={16} />
            <span>History ({history.length})</span>
          </button>
          <button
            type="button"
            className={`tab-btn ${activeTab === 'about' ? 'active' : ''}`}
            onClick={() => setActiveTab('about')}
          >
            <Layers size={16} />
            <span>Methodology</span>
          </button>
        </nav>

        {/* Tab 1: Scanner */}
        {activeTab === 'scanner' && (
          <div className="scanner-grid">
            <Scanner
              onUrlExtracted={handleUrlExtracted}
              isLoading={isLoading}
              error={error}
              onErrorClear={() => setError('')}
            />

            {/* Compact Loader */}
            {isLoading && (
              <div ref={resultsRef} className="loading-box">
                <div className="scanner-radar-mini">
                  <Radar size={18} />
                </div>
                <div className="loading-text-group">
                  <div className="loading-title">
                    <span>Scanning & Analyzing Link...</span>
                  </div>
                  <div className="loading-desc">
                    Evaluating protocol security, credential embedding, IP hosts, ports, and brand spoofing.
                  </div>
                </div>
              </div>
            )}

            {/* Analysis Results & Decoded URL with Auto-Scroll Target */}
            {!isLoading && (extractedUrl || scanResult) && (
              <div ref={resultsRef} className="results-wrapper">
                {extractedUrl && (
                  <DecodedUrlPanel url={extractedUrl} hostname={extractedHostname} />
                )}
                {scanResult && <AnalysisResults result={scanResult} />}
              </div>
            )}
          </div>
        )}

        {/* Tab 2: History */}
        {activeTab === 'history' && (
          <ScanHistory
            history={history}
            onClearHistory={handleClearHistory}
            onSelectHistoryItem={handleSelectHistoryItem}
          />
        )}

        {/* Tab 3: About & Methodology */}
        {activeTab === 'about' && <AboutMethodology />}
      </main>

      <Footer />
    </div>
  );
}
