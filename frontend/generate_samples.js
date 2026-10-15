import QRCode from 'qrcode';
import fs from 'fs';
import path from 'path';

const outDir = path.resolve('../sample_qr_codes');
if (!fs.existsSync(outDir)) {
  fs.mkdirSync(outDir, { recursive: true });
}

const samples = [
  { name: '01_safe_university_url.png', url: 'https://www.cambridge.org/research' },
  { name: '02_http_unencrypted.png', url: 'http://library.univ-portal.edu/books' },
  { name: '03_url_shortener.png', url: 'https://bit.ly/3SecureLogin' },
  { name: '04_phishing_spoofed_brand.png', url: 'https://paypal.account-verify.xyz/login' },
  { name: '05_raw_ip_custom_port.png', url: 'http://192.168.1.100:8080/admin' },
  { name: '06_embedded_credentials.png', url: 'https://root:admin123@web-router.net/auth' }
];

async function generate() {
  for (const s of samples) {
    const filePath = path.join(outDir, s.name);
    await QRCode.toFile(filePath, s.url, {
      width: 400,
      margin: 2,
      color: {
        dark: '#0a0f1d',
        light: '#ffffff'
      }
    });
    console.log(`Generated sample QR: ${s.name} -> ${s.url}`);
  }
}

generate();
