// Generate simple PNG icons using canvas via node
import { createCanvas } from 'canvas';
import { writeFileSync } from 'fs';

function makeIcon(size) {
  const c = createCanvas(size, size);
  const ctx = c.getContext('2d');
  // Background
  ctx.fillStyle = '#0f172a';
  ctx.fillRect(0, 0, size, size);
  // Rounded rect feel — gradient circle
  const grad = ctx.createRadialGradient(size/2, size/2, 0, size/2, size/2, size/2);
  grad.addColorStop(0, '#6366f1');
  grad.addColorStop(1, '#0f172a');
  ctx.fillStyle = grad;
  ctx.beginPath();
  ctx.arc(size/2, size/2, size*0.42, 0, Math.PI*2);
  ctx.fill();
  // Rupee symbol
  ctx.fillStyle = '#ffffff';
  ctx.font = `bold ${Math.round(size*0.38)}px serif`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText('₹', size/2, size/2 + size*0.03);
  return c.toBuffer('image/png');
}

try {
  writeFileSync('public/icon-192.png', makeIcon(192));
  writeFileSync('public/icon-512.png', makeIcon(512));
  console.log('Icons generated');
} catch(e) {
  console.log('canvas not available, creating placeholder icons');
  // Create minimal 1x1 px placeholder PNGs
  const png1x1 = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');
  writeFileSync('public/icon-192.png', png1x1);
  writeFileSync('public/icon-512.png', png1x1);
  console.log('Placeholder icons written');
}
