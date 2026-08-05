import { chromium } from 'playwright';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FRONTEND_DIR = path.join(__dirname, '..');
const SCREENSHOTS_DIR = path.join(FRONTEND_DIR, 'phase2-screenshots');
const ARTIFACT_DIR = 'C:\\Users\\HP-PC\\.gemini\\antigravity-ide\\brain\\2deea050-a65f-4d4e-ac3f-797857de2a58';

async function main() {
  await mkdir(SCREENSHOTS_DIR, { recursive: true });
  await mkdir(ARTIFACT_DIR, { recursive: true });

  console.log('Launching browser...');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  console.log('Navigating to http://localhost:3000/ ...');
  await page.goto('http://localhost:3000/', { waitUntil: 'networkidle' });

  // Determine if we need to sign up or login
  const isLogin = page.url().includes('/login');
  console.log('Current URL:', page.url());

  // Attempt login first
  console.log('Attempting login as antigravity...');
  await page.fill('input[placeholder="e.g. admin"]', 'antigravity');
  await page.fill('input[placeholder="••••••••"]', 'Password123!');
  await page.click('button[type="submit"]');

  await page.waitForTimeout(2000);

  if (page.url().includes('/login')) {
    console.log('Login failed or not redirected. Navigating to signup...');
    await page.goto('http://localhost:3000/signup', { waitUntil: 'networkidle' });
    await page.fill('input[placeholder="e.g. secdev"]', 'antigravity');
    await page.fill('input[placeholder="e.g. dev@company.com"]', 'antigravity@test.com');
    await page.fill('input[placeholder="••••••••"] >> nth=0', 'Password123!');
    await page.fill('input[placeholder="••••••••"] >> nth=1', 'Password123!');
    console.log('Submitting signup form...');
    await page.click('button[type="submit"]');

    await page.waitForTimeout(3000);

    console.log('Navigating to login...');
    await page.goto('http://localhost:3000/login', { waitUntil: 'networkidle' });
    await page.fill('input[placeholder="e.g. admin"]', 'antigravity');
    await page.fill('input[placeholder="••••••••"]', 'Password123!');
    await page.click('button[type="submit"]');
    await page.waitForTimeout(2000);
  }

  console.log('Dashboard URL after login attempt:', page.url());
  if (page.url().includes('/login')) {
    throw new Error('Failed to log in after signup.');
  }

  // Create new project
  console.log('Creating new project...');
  await page.click('button:has-text("New Project")');
  await page.waitForSelector('input[placeholder="e.g. ecommerce-backend"]');
  const projectSuffix = Math.floor(Math.random() * 10000);
  const projectName = `demo-project-${projectSuffix}`;
  await page.fill('input[placeholder="e.g. ecommerce-backend"]', projectName);
  await page.click('button:has-text("Create Project")');

  console.log('Waiting for project page navigation...');
  await page.waitForURL(url => url.pathname.includes('/projects/'));
  const projectUrl = page.url();
  console.log('Project Page URL:', projectUrl);

  await page.waitForTimeout(1000);

  // Upload file
  console.log('Uploading vulnerable_test.py...');
  const uploadInput = await page.locator('input[type="file"]');
  await uploadInput.setInputFiles('c:\\Users\\HP-PC\\Desktop\\security vulnerability decoder and fixer\\vulnerable_test.py');

  console.log('Waiting for upload to finish...');
  await page.waitForSelector('text=vulnerable_test.py', { timeout: 15000 });
  console.log('File uploaded successfully. Triggering scan...');

  // Click Scan Now
  await page.click('button:has-text("Scan Now")');
  console.log('Scan started. Polling for completion...');

  // Wait for scan to complete
  // The ScanPoller renders "Scan in progress..."
  await page.waitForSelector('text=Scan in progress...', { state: 'attached' });
  await page.waitForSelector('text=Scan in progress...', { state: 'detached', timeout: 120000 });
  console.log('Scan completed successfully!');

  // Wait a moment for charts and transitions
  await page.waitForTimeout(3000);

  // Take screenshot of Project page
  console.log('Saving Project page screenshot...');
  const projPath1 = path.join(SCREENSHOTS_DIR, '02-project.png');
  const projPath2 = path.join(ARTIFACT_DIR, 'project_page.png');
  await page.screenshot({ path: projPath1, fullPage: true });
  await page.screenshot({ path: projPath2, fullPage: true });
  console.log(`Saved project screenshots to:\n  - ${projPath1}\n  - ${projPath2}`);

  // Navigate back to Dashboard
  console.log('Navigating back to Dashboard...');
  await page.goto('http://localhost:3000/', { waitUntil: 'networkidle' });
  await page.waitForTimeout(3000);

  // Take screenshot of Dashboard
  console.log('Saving Dashboard screenshot...');
  const dashPath1 = path.join(SCREENSHOTS_DIR, '01-dashboard.png');
  const dashPath2 = path.join(ARTIFACT_DIR, 'dashboard_page.png');
  await page.screenshot({ path: dashPath1, fullPage: true });
  await page.screenshot({ path: dashPath2, fullPage: true });
  console.log(`Saved dashboard screenshots to:\n  - ${dashPath1}\n  - ${dashPath2}`);

  await browser.close();
  console.log('Execution finished successfully!');
}

main().catch(err => {
  console.error('Automation error:', err);
  process.exit(1);
});
