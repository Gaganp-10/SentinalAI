import { chromium } from 'playwright';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.join(__dirname, '..', 'phase2-screenshots');
const BASE = 'http://127.0.0.1:3000';
const PROJECT_ID = process.env.PROJECT_ID || '9358e39c-cbaf-4681-bb7d-23629efa9c26';

async function main() {
  await mkdir(OUT_DIR, { recursive: true });

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });

  await page.goto(`${BASE}/login`, { waitUntil: 'networkidle' });
  await page.fill('input[type="text"], input[name="username"], input[placeholder*="username" i]', 'phase2demo');
  await page.fill('input[type="password"]', 'TestPass123!');
  await page.click('button[type="submit"]');
  await page.waitForURL('**/');
  await page.waitForTimeout(1500);

  await page.screenshot({ path: path.join(OUT_DIR, '01-dashboard.png'), fullPage: true });

  await page.goto(`${BASE}/projects/${PROJECT_ID}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);
  await page.screenshot({ path: path.join(OUT_DIR, '02-project.png'), fullPage: true });

  await browser.close();
  console.log(`Saved screenshots to ${OUT_DIR}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
