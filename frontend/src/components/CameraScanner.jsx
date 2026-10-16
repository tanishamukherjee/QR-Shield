import React, { useEffect, useRef, useState } from 'react';
import { Camera, X } from 'lucide-react';
import { decodeQrFromVideoFrame, getCameraErrorMessage } from '../utils/qrDecoder';

const SCAN_INTERVAL_MS = 200; // ~5 frames per second is plenty for QR codes

/**
 * Live camera QR scanner.
 * Frames are decoded locally with jsQR (nothing is uploaded). The camera is
 * switched off as soon as a code is found, on Cancel, when the page is hidden
 * (tab switch / phone locked), or when the component unmounts.
 */
export default function CameraScanner({ onDetected, onError, onClose }) {
  const videoRef = useRef(null);
  const [isStarting, setIsStarting] = useState(true);

  // Keep the latest callbacks without restarting the camera on every render
  const callbacks = useRef({ onDetected, onError, onClose });
  callbacks.current = { onDetected, onError, onClose };

  useEffect(() => {
    let stream = null;
    let timer = null;
    let stopped = false;
    const canvas = document.createElement('canvas');

    const stopCamera = () => {
      stopped = true;
      clearInterval(timer);
      if (stream) {
        stream.getTracks().forEach(track => track.stop());
      }
      if (videoRef.current) {
        videoRef.current.srcObject = null;
      }
    };

    const startCamera = async () => {
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        callbacks.current.onError(
          'Camera scanning needs a secure (HTTPS) page and a browser with camera support. Please upload an image instead.'
        );
        return;
      }

      try {
        // Prefer the rear camera on phones; laptops fall back to their webcam
        stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: { ideal: 'environment' } },
          audio: false
        });
      } catch (err) {
        if (!stopped) callbacks.current.onError(getCameraErrorMessage(err));
        return;
      }

      // The scanner was closed while the permission prompt was still open
      if (stopped) {
        stream.getTracks().forEach(track => track.stop());
        return;
      }

      const video = videoRef.current;
      video.srcObject = stream;
      await video.play().catch(() => {});
      if (stopped) return; // closed while the video was starting
      setIsStarting(false);

      timer = setInterval(() => {
        const text = decodeQrFromVideoFrame(video, canvas);
        if (text) {
          stopCamera();
          callbacks.current.onDetected(text);
        }
      }, SCAN_INTERVAL_MS);
    };

    const handleVisibilityChange = () => {
      if (document.hidden) {
        stopCamera();
        callbacks.current.onClose();
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    startCamera();

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      stopCamera();
    };
  }, []);

  return (
    <div className="camera-panel">
      <div className="camera-viewport">
        <video ref={videoRef} className="camera-video" playsInline muted autoPlay />
        <div className="camera-frame" aria-hidden="true" />
        {isStarting && <div className="camera-overlay-text">Starting camera…</div>}
      </div>

      <div className="camera-footer">
        <span className="camera-status">
          <Camera size={14} />
          {isStarting
            ? 'Waiting for camera permission…'
            : 'Point the camera at a QR code. It is read in your browser, never uploaded.'}
        </span>
        <button type="button" className="btn-camera-cancel" onClick={() => callbacks.current.onClose()}>
          <X size={14} />
          Cancel
        </button>
      </div>
    </div>
  );
}
