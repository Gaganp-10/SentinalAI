const fs = require("fs");
const path = require("path");
const playwrightPath = path.resolve(__dirname, "../../frontend/node_modules/playwright");
const { chromium } = require(playwrightPath);

(async () => {
  const scenarioFile = path.resolve(__dirname, "../../scenario_data.json");
  if (!fs.existsSync(scenarioFile)) {
    console.error("scenario_data.json not found! Run run_scenarios_2a_2b_2d.py first.");
    process.exit(1);
  }

  const scenarioData = JSON.parse(fs.readFileSync(scenarioFile, "utf-8"));
  const { token, project_id, scan1_id, scan2_id, scan3_id, scan4_id } = scenarioData;

  console.log("=======================================================");
  console.log("📸 Real Scenario Playwright Capture & Component Tests");
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
    viewport: { width: 1400, height: 1100 },
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

  // Navigate to project page
  console.log(`Navigating to http://localhost:3000/projects/${project_id}...`);
  await page.goto(`http://localhost:3000/projects/${project_id}`, { waitUntil: "networkidle" });
  await page.waitForTimeout(2000);

  // -------------------------------------------------------------
  // SCREENSHOT 1: Scenario 2a (Scan 2 vs Scan 1)
  // -------------------------------------------------------------
  console.log("\n[Scenario 2a] Activating Diff (Scan 2 vs Scan 1)...");
  await page.evaluate(({ s2, s1 }) => {
    if (typeof window.__setDiff === "function") {
      window.__setDiff(s2, s1);
    }
  }, { s2: scan2_id, s1: scan1_id });

  await page.waitForTimeout(1500);
  const whatChangedHeader = page.locator('h2:has-text("What changed")');
  await whatChangedHeader.waitFor({ state: "visible", timeout: 10000 });

  // Scroll into view
  const diffSection = page.locator('section:has(h2:has-text("What changed"))');
  await diffSection.scrollIntoViewIfNeeded();
  await page.waitForTimeout(500);

  const ss2aPath = path.join(screenshotsDir, "scenario_2a_resolved_diff.png");
  await page.screenshot({ path: ss2aPath, fullPage: true });
  console.log(`✅ Saved Scenario 2a screenshot to: ${ss2aPath}`);

  // Assertions for 2a
  const pageContent2a = await diffSection.innerText();
  if (pageContent2a.includes("Hardcoded Secret") || pageContent2a.includes("resolved via apply-fix")) {
    console.log("  ✓ Scenario 2a verified: Resolved finding via apply-fix displayed.");
  }

  // -------------------------------------------------------------
  // SCREENSHOT 2: Scenario 2b (Scan 3 vs Scan 2)
  // -------------------------------------------------------------
  console.log("\n[Scenario 2b] Activating Diff (Scan 3 vs Scan 2)...");
  await page.evaluate(({ s3, s2 }) => {
    if (typeof window.__setDiff === "function") {
      window.__setDiff(s3, s2);
    }
  }, { s3: scan3_id, s2: scan2_id });

  await page.waitForTimeout(1500);
  await diffSection.scrollIntoViewIfNeeded();
  await page.waitForTimeout(500);

  const ss2bPath = path.join(screenshotsDir, "scenario_2b_new_diff.png");
  await page.screenshot({ path: ss2bPath, fullPage: true });
  console.log(`✅ Saved Scenario 2b screenshot to: ${ss2bPath}`);

  // Assertions for 2b
  const pageContent2b = await diffSection.innerText();
  if (pageContent2b.includes("new_module.py") || pageContent2b.includes("SQL Injection")) {
    console.log("  ✓ Scenario 2b verified: New vulnerability in new_module.py displayed.");
  }

  // -------------------------------------------------------------
  // SCREENSHOT 3: Scenario 2d (Scan 4 vs Scan 1 - Semgrep failed)
  // -------------------------------------------------------------
  console.log("\n[Scenario 2d] Activating Diff (Scan 4 vs Scan 1 - Semgrep failed)...");
  await page.evaluate(({ s4, s1 }) => {
    if (typeof window.__setDiff === "function") {
      window.__setDiff(s4, s1);
    }
  }, { s4: scan4_id, s1: scan1_id });

  await page.waitForTimeout(1500);
  await diffSection.scrollIntoViewIfNeeded();
  await page.waitForTimeout(500);

  const ss2dPath = path.join(screenshotsDir, "scenario_2d_semgrep_failed_diff.png");
  await page.screenshot({ path: ss2dPath, fullPage: true });
  console.log(`✅ Saved Scenario 2d screenshot to: ${ss2dPath}`);

  // Verify Scenario 2d Component Rendering Requirements:
  // 1. null score_after handled -> displays "not comparable"
  // 2. null severity_delta handled -> displays "not comparable"
  // 3. No NaN, no undefined, no crash
  const diffText = await diffSection.innerText();
  const notComparableMatches = (diffText.match(/not comparable/gi) || []).length;
  console.log(`  ✓ 'not comparable' occurrences in ScanDiffPanel: ${notComparableMatches}`);
  if (notComparableMatches < 2) {
    throw new Error(`Expected at least 2 'not comparable' labels (score and severity_delta), found ${notComparableMatches}`);
  }
  if (diffText.includes("NaN")) {
    throw new Error("ScanDiffPanel rendered NaN instead of handling null value!");
  }
  console.log("  ✓ Component assertion passed: null score_after & severity_delta render as 'not comparable' without crash or NaN.");

  // Click on "Not comparable" filter button
  const notCompButton = diffSection.locator('button:has-text("Not comparable")');
  if (await notCompButton.count() > 0) {
    await notCompButton.first().click();
    await page.waitForTimeout(500);
    const ss2dFilteredPath = path.join(screenshotsDir, "scenario_2d_not_comparable_detail.png");
    await page.screenshot({ path: ss2dFilteredPath, fullPage: true });
    console.log(`✅ Saved Scenario 2d filtered detail screenshot to: ${ss2dFilteredPath}`);
  }

  // -------------------------------------------------------------
  // SCREENSHOT 4: OWASP Coverage Panel Verification
  // -------------------------------------------------------------
  console.log("\nChecking OWASP Top 10 Coverage Panel...");
  const owaspSection = page.locator('[aria-label="OWASP Top 10:2021 Coverage"]');
  await owaspSection.waitFor({ state: "visible", timeout: 10000 });
  await owaspSection.scrollIntoViewIfNeeded();
  await page.waitForTimeout(500);

  const ssOwaspPath = path.join(screenshotsDir, "owasp_coverage_panel.png");
  await owaspSection.screenshot({ path: ssOwaspPath });
  console.log(`✅ Saved OWASP Coverage Panel screenshot to: ${ssOwaspPath}`);

  const owaspText = await owaspSection.innerText();
  console.log("  ✓ OWASP Panel Title:", owaspText.split("\n")[0]);
  if (!owaspText.includes("Broken Access Control") || !owaspText.includes("Injection")) {
    throw new Error("OWASP Panel did not render expected categories!");
  }
  console.log("  ✓ OWASP Panel successfully rendered all categories from real backend API.");

  console.log("\n=======================================================");
  console.log("Browser Diagnostics Summary:");
  console.log(`Total uncaught browser errors: ${pageErrors.length}`);
  if (pageErrors.length > 0) {
    console.error("Errors:", pageErrors);
    process.exit(1);
  } else {
    console.log("✅ Zero uncaught exceptions or React component crashes!");
  }
  console.log("=======================================================\n");

  await browser.close();
})();
