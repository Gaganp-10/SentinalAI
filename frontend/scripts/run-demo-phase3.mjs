import { chromium } from 'playwright';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FRONTEND_DIR = path.join(__dirname, '..');
const SCREENSHOTS_DIR = path.join(FRONTEND_DIR, 'phase3-screenshots');
const ARTIFACT_DIR = 'C:\\Users\\HP-PC\\.gemini\\antigravity-ide\\brain\\2deea050-a65f-4d4e-ac3f-797857de2a58';

async function main() {
  await mkdir(SCREENSHOTS_DIR, { recursive: true });
  await mkdir(ARTIFACT_DIR, { recursive: true });

  console.log('Launching browser...');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  page.on('console', msg => console.log('PAGE LOG:', msg.text()));
  page.on('pageerror', err => console.log('PAGE ERROR:', err.message));

  console.log('Navigating to http://localhost:3000/ ...');
  await page.goto('http://localhost:3000/', { waitUntil: 'networkidle' });

  // Login
  console.log('Attempting login as antigravity...');
  await page.fill('input[placeholder="e.g. admin"]', 'antigravity');
  await page.fill('input[placeholder="••••••••"]', 'Password123!');
  await page.click('button[type="submit"]');

  await page.waitForTimeout(2000);

  // If login failed, register first
  if (page.url().includes('/login')) {
    console.log('Login failed. Navigating to signup...');
    await page.goto('http://localhost:3000/signup', { waitUntil: 'networkidle' });
    await page.fill('input[placeholder="e.g. secdev"]', 'antigravity');
    await page.fill('input[placeholder="e.g. dev@company.com"]', 'antigravity@test.com');
    await page.fill('input[placeholder="••••••••"] >> nth=0', 'Password123!');
    await page.fill('input[placeholder="••••••••"] >> nth=1', 'Password123!');
    await page.click('button[type="submit"]');

    await page.waitForTimeout(3000);

    await page.goto('http://localhost:3000/login', { waitUntil: 'networkidle' });
    await page.fill('input[placeholder="e.g. admin"]', 'antigravity');
    await page.fill('input[placeholder="••••••••"]', 'Password123!');
    await page.click('button[type="submit"]');
    await page.waitForTimeout(2000);
  }

  console.log('Logged in. Creating new project...');
  await page.click('button:has-text("New Project")');
  await page.waitForSelector('input[placeholder="e.g. ecommerce-backend"]');
  const projectSuffix = Math.floor(Math.random() * 10000);
  const projectName = `phase3-project-${projectSuffix}`;
  await page.fill('input[placeholder="e.g. ecommerce-backend"]', projectName);
  await page.click('button:has-text("Create Project")');

  console.log('Waiting for project page navigation...');
  await page.waitForURL(url => url.pathname.includes('/projects/'));
  console.log('On project page. Uploading vulnerable_test.py...');

  const uploadInput = await page.locator('input[type="file"]');
  await uploadInput.setInputFiles('c:\\Users\\HP-PC\\Desktop\\security vulnerability decoder and fixer\\vulnerable_test.py');

  await page.waitForSelector('text=vulnerable_test.py', { timeout: 15000 });
  console.log('File uploaded. Triggering scan...');

  await page.click('button:has-text("Scan Now")');
  await page.waitForSelector('text=Scan in progress...', { state: 'attached' });
  console.log('Scan running. Waiting for completion...');
  await page.waitForSelector('text=Scan in progress...', { state: 'detached', timeout: 120000 });
  console.log('Scan completed successfully!');

  await page.waitForTimeout(3000);

  // 1. Capture Project page with Recent Activity / Scan History timeline
  console.log('Saving Project page with Recent Activity feed...');
  await page.locator('text=Scan History & Recent Activity').scrollIntoViewIfNeeded();
  await page.waitForTimeout(1000);
  
  const activityPath1 = path.join(SCREENSHOTS_DIR, '04-recent-activity.png');
  const activityPath2 = path.join(ARTIFACT_DIR, 'recent_activity_page.png');
  await page.screenshot({ path: activityPath1 });
  await page.screenshot({ path: activityPath2 });

  // 2. Go to Scan Results Page
  console.log('Navigating to Scan Results...');
  const viewFindingsBtn = await page.locator('button:has-text("View Findings")').first();
  await viewFindingsBtn.scrollIntoViewIfNeeded();
  await viewFindingsBtn.click();
  await page.waitForURL(url => url.pathname.includes('/results'));
  await page.waitForTimeout(4000);

  console.log('Saving Scan Results page with Hexagon Strip & Vulnerability list...');
  const resultsPath1 = path.join(SCREENSHOTS_DIR, '03-scan-results.png');
  const resultsPath2 = path.join(ARTIFACT_DIR, 'scan_results_page.png');
  await page.screenshot({ path: resultsPath1, fullPage: true });
  await page.screenshot({ path: resultsPath2, fullPage: true });

  // 3. Go to Vulnerability Detail Page
  try {
    console.log('Navigating to first Vulnerability Detail view...');
    await page.click('tbody tr:first-child');

    console.log('Waiting for Vulnerability Detail page layout to render...');
    await page.waitForSelector('text=Security Analysis', { timeout: 25000 });
    await page.waitForTimeout(4000);

    console.log('Saving Vulnerability Detail page...');
    const detailPath1 = path.join(SCREENSHOTS_DIR, '05-vuln-detail.png');
    const detailPath2 = path.join(ARTIFACT_DIR, 'vuln_detail_page.png');
    await page.screenshot({ path: detailPath1, fullPage: true });
    await page.screenshot({ path: detailPath2, fullPage: true });
  } catch (err) {
    console.log('NAVIGATION ERROR occurred!');
    console.log('Current URL:', page.url());
    const failurePath = path.join(ARTIFACT_DIR, 'failure_state.png');
    await page.screenshot({ path: failurePath, fullPage: true });
    console.log(`Saved failure state screenshot to: ${failurePath}`);
    throw err;
  }

  await browser.close();
  console.log('Automation script execution finished successfully!');
}

main().catch(err => {
  console.error('Automation error:', err);
  process.exit(1);
});
