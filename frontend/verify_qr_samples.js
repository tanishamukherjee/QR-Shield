import fs from 'fs';
import path from 'path';
import { PNG } from 'pngjs';
import jsQR from 'jsqr';
import { fileURLToPath } from 'url';

// Resolved from this script's location, so it works from any working directory
const sampleDir = fileURLToPath(new URL('../sample_qr_codes/', import.meta.url));
const files = fs.readdirSync(sampleDir).filter(f => f.endsWith('.png'));

console.log(`Verifying QR decoding on ${files.length} sample images using jsQR:`);

let allPassed = true;
for (const file of files) {
  const filePath = path.join(sampleDir, file);
  const data = fs.readFileSync(filePath);
  const png = PNG.sync.read(data);
  const code = jsQR(new Uint8ClampedArray(png.data), png.width, png.height);
  if (!code || !code.data) {
    console.error(`❌ FAILED: ${file}`);
    allPassed = false;
  } else {
    console.log(`✅ ${file} -> "${code.data}"`);
  }
}

if (allPassed) {
  console.log('\nAll sample QR images successfully decoded with jsQR!');
} else {
  process.exit(1);
}
