import jsQR from 'jsQR';

const ALLOWED_MIME_TYPES = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'];
const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB

/**
 * Validates file format and size constraints.
 */
export function validateImageFile(file) {
  if (!file) {
    throw new Error('Please select an image file to scan.');
  }

  if (!ALLOWED_MIME_TYPES.includes(file.type.toLowerCase())) {
    throw new Error('Unsupported image format. Please upload a PNG, JPEG, or WebP image.');
  }

  if (file.size > MAX_FILE_SIZE_BYTES) {
    const sizeMb = (file.size / (1024 * 1024)).toFixed(1);
    throw new Error(`File is too large (${sizeMb} MB). Maximum allowed size is 5 MB.`);
  }

  return true;
}

/**
 * Reads an image file into an Image element and decodes any QR code using jsQR.
 * Does not transmit the image to any external server.
 */
export async function decodeQrFromImage(file) {
  validateImageFile(file);

  return new Promise((resolve, reject) => {
    const reader = new FileReader();

    reader.onerror = () => {
      reject(new Error('Failed to read image file from local disk.'));
    };

    reader.onload = () => {
      const img = new Image();

      img.onerror = () => {
        reject(new Error('Could not parse image data. Ensure the file is a valid image.'));
      };

      img.onload = () => {
        try {
          const canvas = document.createElement('canvas');
          const ctx = canvas.getContext('2d', { willReadFrequently: true });

          // Scale down very large images to improve decoding speed and memory usage
          let width = img.naturalWidth || img.width;
          let height = img.naturalHeight || img.height;
          const maxDim = 1200;

          if (width > maxDim || height > maxDim) {
            if (width > height) {
              height = Math.round((height * maxDim) / width);
              width = maxDim;
            } else {
              width = Math.round((width * maxDim) / height);
              height = maxDim;
            }
          }

          canvas.width = width;
          canvas.height = height;
          ctx.drawImage(img, 0, 0, width, height);

          const imageData = ctx.getImageData(0, 0, width, height);
          let code = jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: 'attemptBoth'
          });

          // Second attempt: grayscale boost for tricky lighting
          if (!code) {
            const data = imageData.data;
            for (let i = 0; i < data.length; i += 4) {
              const avg = (data[i] + data[i + 1] + data[i + 2]) / 3;
              data[i] = avg;
              data[i + 1] = avg;
              data[i + 2] = avg;
            }
            ctx.putImageData(imageData, 0, 0);
            code = jsQR(imageData.data, imageData.width, imageData.height, {
              inversionAttempts: 'attemptBoth'
            });
          }

          if (code && code.data && code.data.trim()) {
            resolve(code.data.trim());
          } else {
            reject(
              new Error(
                'No QR code detected in this image. Please ensure the QR code is centered, well-lit, and in focus.'
              )
            );
          }
        } catch (err) {
          reject(new Error(`QR decoding error: ${err.message}`));
        }
      };

      img.src = reader.result;
    };

    reader.readAsDataURL(file);
  });
}

/**
 * Validates whether the decoded content is a valid HTTP(S) URL.
 */
export function validateScannedUrl(rawText) {
  if (!rawText || typeof rawText !== 'string') {
    throw new Error('QR code payload is empty.');
  }

  const trimmed = rawText.trim();

  // Basic scheme test before full URL parse
  const schemeMatch = trimmed.match(/^([a-zA-Z0-9+.-]+):/);
  if (!schemeMatch) {
    throw new Error(
      `Decoded content ("${trimmed.slice(0, 40)}...") is plain text or missing a protocol. QRShield analyzes web links (http:// and https://) only.`
    );
  }

  const scheme = schemeMatch[1].toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') {
    throw new Error(
      `Unsupported scheme "${scheme}:". QRShield protects against web threats and rejects non-web protocols (such as ${scheme}:, tel:, mailto:, sms:).`
    );
  }

  try {
    const urlObj = new URL(trimmed);
    if (!urlObj.hostname) {
      throw new Error('URL is missing a valid hostname.');
    }
    return trimmed;
  } catch (err) {
    throw new Error(`Malformed URL structure: ${err.message}`);
  }
}
