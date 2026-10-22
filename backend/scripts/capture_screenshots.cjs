const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

(async () => {
  const scenarioFile = path.resolve(__dirname, "../../scenario_data.json");
  if (!fs.existsSync(scenarioFile)) {
    console.error("scenario_data.json not found! Run run_scenarios_2a_2b_2d.py first.");
    process.exit(1);
  }

  const scenarioData = JSON.parse(fs.readFileSync(scenarioFile, "utf-8"));
  const { token, project_id, scan1_id, scan2_id, scan3_id, scan4_id } = scenarioData;

  console.log("=======================================================");
  console.log("📸 Starting Real Scenario Playwright Capture");
  console.log(`Project: ${project_id}`);
  console.log(`Scan 1 (Base): ${scan1_id}`);
  console.log(`Scan 2 (2a Apply-Fix): ${scan2_id}`);
  console.log(`Scan 3 (2b New Vuln): ${scan3_id}`);
  console.log(`Scan 4 (2d Semgrep Failed): ${scan4_id}`);
  console.log("=======================================================\n");

  const screenshotsDir = path.resolve(__dirname, "../../real_scenario_screenshots");
  if (!fs.existsSync(screenshotsDir)) {
    fs.mkdirSync(screenshotsDir, { recursive: true });
  }

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1400, height: 1000 },
  });
  const page = await context.newPage();

  // Listen to console and page errors
  const pageErrors = [];
  page.on("pageerror", (err) => {
    console.error("Browser Page Error:", err.message);
    pageErrors.push(err.message);
  });
  page.on("console", (msg) => {
    if (msg.type() === "error") {
      console.log("Browser Console Error:", msg.text());
    }
  });

  // 1. Authenticate by setting token in localStorage
  await page.goto("http://localhost:3000/");
  await page.evaluate((jwt) => {
    localStorage.setItem("access_token", jwt);
    localStorage.setItem("sast_token", jwt);
  }, token);

  // -------------------------------------------------------------
  // SCREENSHOT 1: Scenario 2a (Scan 2 vs Scan 1)
  // -------------------------------------------------------------
  console.log("Capturing Scenario 2a (Resolved via apply-fix)...");
  await page.goto(`http://localhost:3000/projects/${project_id}`, { waitUntil: "networkidle" });
  await page.waitForTimeout(1500);

  // Inject or open diff panel for Scan 2 vs Scan 1
  // We can fetch diff 2a directly from API and verify component render or set diff state
  // Let's trigger the diff endpoint and view ScanDiffPanel
  await page.evaluate(async ({ pid, s2, s1 }) => {
    const res = await fetch(`/api/projects/${pid}/scans/${s2}/diff?base=${s1}`, {
      headers: { Authorization: `Bearer ${localStorage.getItem("access_token")}` }
    });
    const diff = await res.json();
    window.__currentDiff = diff;
  }, { pid: project_id, s2: scan2_id, s1: scan1_id });

  // Select scan2 from history if available or wait for scan diff
  const scan2Button = page.locator(`button:has-text("${scan2_id.slice(0, 8)}")`);
  if (await scan2Button.count() > 0) {
    await scan2Button.first().click();
    await page.waitForTimeout(1000);
  }

  const ss2aPath = path.join(screenshotsDir, "scenario_2a_resolved_diff.png");
  await page.screenshot({ path: ss2aPath, fullPage: true });
  console.log(` Saved Scenario 2a screenshot to: ${ss2aPath}`);

  // -------------------------------------------------------------
  // SCREENSHOT 2: Scenario 2b (Scan 3 vs Scan 2)
  // -------------------------------------------------------------
  console.log("Capturing Scenario 2b (New vulnerability introduced)...");
  const scan3Button = page.locator(`button:has-text("${scan3_id.slice(0, 8)}")`);
  if (await scan3Button.count() > 0) {
    await scan3Button.first().click();
    await page.waitForTimeout(1000);
  }

  const ss2bPath = path.join(screenshotsDir, "scenario_2b_new_diff.png");
  await page.screenshot({ path: ss2bPath, fullPage: true });
  console.log(` Saved Scenario 2b screenshot to: ${ss2bPath}`);

  // -------------------------------------------------------------
  // SCREENSHOT 3: Scenario 2d (Scan 4 vs Scan 1 - Semgrep failed)
  // -------------------------------------------------------------
  console.log("Capturing Scenario 2d (Semgrep failed / not comparable)...");
  const scan4Button = page.locator(`button:has-text("${scan4_id.slice(0, 8)}")`);
  if (await scan4Button.count() > 0) {
    await scan4Button.first().click();
    await page.waitForTimeout(1000);
  }

  const ss2dPath = path.join(screenshotsDir, "scenario_2d_semgrep_failed_diff.png");
  await page.screenshot({ path: ss2dPath, fullPage: true });
  console.log(` Saved Scenario 2d screenshot to: ${ss2dPath}`);

  // -------------------------------------------------------------
  // SCREENSHOT 4: OWASP Coverage Panel Verification
  // -------------------------------------------------------------
  console.log("Checking OWASP Top 10 Coverage Panel...");
  const owaspSection = page.locator('[aria-label="OWASP Top 10:2021 Coverage"]');
  if (await owaspSection.count() > 0) {
    await owaspSection.scrollIntoViewIfNeeded();
    await page.waitForTimeout(500);
    const ssOwaspPath = path.join(screenshotsDir, "owasp_coverage_panel.png");
    await owaspSection.screenshot({ path: ssOwaspPath });
    console.log(` Saved OWASP Coverage Panel screenshot to: ${ssOwaspPath}`);
  }

  console.log("\n=======================================================");
  console.log("Component Test Check Results:");
  console.log(`Total page errors encountered: ${pageErrors.length}`);
  if (pageErrors.length > 0) {
    console.error("Errors:", pageErrors);
  } else {
    console.log("✅ Zero uncaught browser exceptions or component crashes!");
  }
  console.log("=======================================================\n");

  await browser.close();
})();
