import React, { useState, useRef } from 'react';
import { Upload, QrCode, Globe, AlertCircle, FileImage, X, Zap, Camera } from 'lucide-react';
import { decodeQrFromImage, validateScannedUrl } from '../utils/qrDecoder';
import CameraScanner from './CameraScanner';

const PRESETS = [
  { label: 'Safe HTTPS', url: 'https://www.cambridge.org/research' },
  { label: 'Plain HTTP', url: 'http://library.univ-portal.edu/books' },
  { label: 'URL Shortener', url: 'https://bit.ly/3SecureLogin' },
  { label: 'Raw IP Host', url: 'http://192.168.1.100:8080/admin' },
  { label: 'Spoofed Brand', url: 'https://paypal.account-verify.xyz/login' },
  { label: 'Embedded Auth', url: 'https://root:admin123@web-router.net/auth' },
  { label: 'Disguised @ Link', url: 'https://accounts.google.com@secure-check.top/' },
  { label: 'Look-alike Domain', url: 'https://paypa1.com/login' }
];

export default function Scanner({ onUrlExtracted, isLoading, error, onErrorClear }) {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [isDecoding, setIsDecoding] = useState(false);
  const [manualUrl, setManualUrl] = useState('');
  const [isCameraOpen, setIsCameraOpen] = useState(false);
  const fileInputRef = useRef(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const processFile = async (file) => {
    if (!file) return;
    onErrorClear();
    setIsCameraOpen(false);
    setSelectedFile(file);
    setIsDecoding(true);

    try {
      // 1. Decode QR code locally using jsQR
      const decodedText = await decodeQrFromImage(file);
      // 2. Validate extracted text as a supported HTTP(S) URL
      const validUrl = validateScannedUrl(decodedText);
      // 3. Pass to parent for threat analysis
      onUrlExtracted(validUrl, 'qr_image');
    } catch (err) {
      onUrlExtracted(null, 'error', err.message);
    } finally {
      setIsDecoding(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      processFile(e.target.files[0]);
    }
  };

  const handleManualSubmit = (e) => {
    e.preventDefault();
    onErrorClear();
    setIsCameraOpen(false);
    if (!manualUrl.trim()) return;

    try {
      const validUrl = validateScannedUrl(manualUrl.trim());
      onUrlExtracted(validUrl, 'manual_input');
    } catch (err) {
      onUrlExtracted(null, 'error', err.message);
    }
  };

  const handlePresetClick = (presetUrl) => {
    setManualUrl(presetUrl);
    onErrorClear();
    setIsCameraOpen(false);
    try {
      const validUrl = validateScannedUrl(presetUrl);
      onUrlExtracted(validUrl, 'preset');
    } catch (err) {
      onUrlExtracted(null, 'error', err.message);
    }
  };

  const handleOpenCamera = (e) => {
    e.stopPropagation();
    onErrorClear();
    setSelectedFile(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
    setIsCameraOpen(true);
  };

  // A QR code was found in the live camera feed: same checks as an uploaded image
  const handleCameraDetected = (decodedText) => {
    setIsCameraOpen(false);
    try {
      const validUrl = validateScannedUrl(decodedText);
      onUrlExtracted(validUrl, 'camera');
    } catch (err) {
      onUrlExtracted(null, 'error', err.message);
    }
  };

  const handleCameraError = (message) => {
    setIsCameraOpen(false);
    onUrlExtracted(null, 'error', message);
  };

  const handleClearSelected = () => {
    setSelectedFile(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
    onErrorClear();
  };

  return (
    <section className="card scanner-card">
      <div className="card-title">
        <QrCode size={20} className="text-accent" />
        <h3>Scan QR Code for Embedded Threats</h3>
      </div>
      <p className="card-subtitle">
        Upload an image or scan with your camera. Decoding is performed client-side in your browser for privacy.
      </p>

      {/* Live camera scanner replaces the drop zone while it is open */}
      {isCameraOpen ? (
        <CameraScanner
          onDetected={handleCameraDetected}
          onError={handleCameraError}
          onClose={() => setIsCameraOpen(false)}
        />
      ) : (
        <div
          className={`dropzone ${dragActive ? 'drag-active' : ''}`}
          onDragEnter={handleDrag}
          onDragOver={handleDrag}
          onDragLeave={handleDrag}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept="image/png, image/jpeg, image/webp"
            style={{ display: 'none' }}
            onChange={handleFileChange}
            disabled={isLoading}
          />
          <div className="dropzone-icon">
            <Upload size={28} />
          </div>
          <div className="dropzone-title">Drag & drop QR image here</div>
          <div className="dropzone-hint">Supports PNG, JPEG, or WebP (Max 5 MB)</div>
          <div className="dropzone-actions">
            <button
              type="button"
              className="btn-upload"
              disabled={isLoading}
              onClick={(e) => {
                e.stopPropagation();
                fileInputRef.current?.click();
              }}
            >
              <FileImage size={16} />
              Browse Files
            </button>
            <button
              type="button"
              className="btn-camera"
              disabled={isLoading}
              onClick={handleOpenCamera}
            >
              <Camera size={16} />
              Scan with Camera
            </button>
          </div>
        </div>
      )}

      {selectedFile && (
        <div className="file-preview">
          <div className="file-info">
            <FileImage size={18} className="text-accent" />
            <div>
              <div className="file-name">{selectedFile.name}</div>
              <div className="file-size">{(selectedFile.size / 1024).toFixed(1)} KB</div>
            </div>
          </div>
          <button
            type="button"
            className="error-close"
            onClick={handleClearSelected}
            title="Remove file"
          >
            <X size={16} />
          </button>
        </div>
      )}

      <div className="divider">or test via manual url</div>

      {/* Manual URL Input Form */}
      <form onSubmit={handleManualSubmit} className="url-form">
        <div className="input-group">
          <Globe size={18} className="input-icon" />
          <input
            type="text"
            className="input-url"
            placeholder="https://example.com/login"
            value={manualUrl}
            onChange={(e) => setManualUrl(e.target.value)}
            disabled={isLoading}
          />
        </div>
        <button type="submit" className="btn-primary" disabled={isLoading || !manualUrl.trim()}>
          Inspect Link
        </button>
      </form>

      {/* Presets for quick evaluation */}
      <div className="preset-section">
        <div className="preset-title">Test Scenarios (Instant Heuristic Verification):</div>
        <div className="preset-chips">
          {PRESETS.map((p, idx) => (
            <button
              key={idx}
              type="button"
              className="chip-btn"
              disabled={isLoading}
              onClick={() => handlePresetClick(p.url)}
              title={`Test ${p.url}`}
            >
              <Zap size={12} />
              <span>{p.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="error-banner">
          <div className="error-content">
            <AlertCircle size={18} />
            <span>{error}</span>
          </div>
          <button type="button" className="error-close" onClick={onErrorClear}>
            <X size={16} />
          </button>
        </div>
      )}
    </section>
  );
}
