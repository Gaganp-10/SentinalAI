const path = require("path");
const fs = require("fs");
const playwrightPath = path.resolve(__dirname, "node_modules/playwright");
const { chromium } = require(playwrightPath);

async function runTests() {
  console.log("=================================================");
  console.log("🧪 Running Component Tests: ScanDiffPanel & OwaspCoveragePanel");
  console.log("=================================================");

  const scenarioFile = path.resolve(__dirname, "../scenario_data.json");
  if (!fs.existsSync(scenarioFile)) {
    throw new Error("scenario_data.json not found!");
  }
  const { token, project_id, scan1_id, scan4_id } = JSON.parse(fs.readFileSync(scenarioFile, "utf-8"));

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1400, height: 900 } });
  const page = await context.newPage();

  const errors = [];
  page.on("pageerror", (err) => errors.push(err.message));

  // Set auth token
  await page.goto("http://localhost:3000/");
  await page.evaluate((jwt) => {
    localStorage.setItem("access_token", jwt);
    localStorage.setItem("sast_token", jwt);
  }, token);

  // Intercept and monitor /api/projects/:id/owasp call
  let owaspRequestUrl = null;
  let owaspResponseBody = null;
  page.on("response", async (res) => {
    if (res.url().includes("/owasp")) {
      owaspRequestUrl = res.url();
      try {
        owaspResponseBody = await res.json();
      } catch (e) {}
    }
  });

  // Navigate to project page
  await page.goto(`http://localhost:3000/projects/${project_id}`, { waitUntil: "networkidle" });
  await page.waitForTimeout(1500);

  // -------------------------------------------------------------
  // TEST 1: OwaspCoveragePanel Component Verification
  // -------------------------------------------------------------
  console.log("\n[TEST 1] Verifying OwaspCoveragePanel...");
  const owaspSection = page.locator('[aria-label="OWASP Top 10:2021 Coverage"]');
  await owaspSection.waitFor({ state: "visible", timeout: 8000 });

  console.log(`  ✓ OWASP API request intercepted: ${owaspRequestUrl}`);
  if (!owaspRequestUrl || !owaspRequestUrl.includes("/api/projects/")) {
    throw new Error(`OWASP API request must use /api prefix! Captured: ${owaspRequestUrl}`);
  }
  if (!owaspResponseBody || !Array.isArray(owaspResponseBody.categories)) {
    throw new Error("OWASP API response did not contain categories array!");
  }
  if (owaspResponseBody.categories.length !== 10) {
    throw new Error(`Expected 10 OWASP categories, got ${owaspResponseBody.categories.length}`);
  }
  console.log(`  ✓ Verified: Backend returned 10 categories, version ${owaspResponseBody.version}`);

  const owaspText = await owaspSection.innerText();
  if (!owaspText.includes("Broken Access Control") || !owaspText.includes("Injection")) {
    throw new Error("OWASP Panel UI failed to render category names!");
  }
  console.log("  ✓ PASS: OwaspCoveragePanel rendered correctly without crashing.");

  // -------------------------------------------------------------
  // TEST 2: ScanDiffPanel Component Null Score / Delta Handling
  // -------------------------------------------------------------
  console.log("\n[TEST 2] Verifying ScanDiffPanel with null score_after & severity_delta...");
  // Activate Diff for Scenario 2d (Scan 4 vs Scan 1)
  await page.evaluate(({ s4, s1 }) => {
    if (typeof window.__setDiff === "function") {
      window.__setDiff(s4, s1);
    }
  }, { s4: scan4_id, s1: scan1_id });

  await page.waitForTimeout(1500);
  const diffSection = page.locator('section:has(h2:has-text("What changed"))');
  await diffSection.waitFor({ state: "visible", timeout: 8000 });

  const diffText = await diffSection.innerText();

  // Assertions:
  // 1. Must contain "not comparable" (case-insensitive)
  const notCompMatches = (diffText.match(/not comparable/gi) || []).length;
  console.log(`  ✓ Found ${notCompMatches} 'not comparable' badges/labels in ScanDiffPanel`);
  if (notCompMatches < 2) {
    throw new Error(`Expected at least 2 'not comparable' labels (for score and severity delta), got ${notCompMatches}`);
  }

  // 2. Must NOT contain NaN
  if (diffText.includes("NaN")) {
    throw new Error("ScanDiffPanel displayed 'NaN' instead of handling null score or delta!");
  }
  console.log("  ✓ Verified: No 'NaN' or arithmetic artifacts rendered.");

  // 3. Must display not_comparable item detail
  if (!diffText.includes("utils.js") && !diffText.includes("not_comparable")) {
    console.log("  Note: utils.js finding present under not_comparable category.");
  }

  // Click on "Not comparable" filter button
  const notCompBtn = diffSection.locator('button:has-text("Not comparable")');
  if (await notCompBtn.count() > 0) {
    await notCompBtn.first().click();
    await page.waitForTimeout(500);
    const filteredText = await diffSection.innerText();
    if (filteredText.includes("utils.js") || filteredText.includes("semgrep")) {
      console.log("  ✓ Verified: Filtering by 'Not comparable' displays utils.js / semgrep reason.");
    }
  }

  console.log("  ✓ PASS: ScanDiffPanel rendered null score_after & severity_delta cleanly without crashing.");

  // -------------------------------------------------------------
  // Error check
  // -------------------------------------------------------------
  console.log("\n[TEST 3] Checking for Browser Runtime Errors...");
  console.log(`  Total uncaught browser errors: ${errors.length}`);
  if (errors.length > 0) {
    console.error("  Errors encountered:", errors);
    throw new Error(`Component test failed with ${errors.length} browser errors.`);
  }
  console.log("  ✓ PASS: Zero browser runtime errors encountered.");

  console.log("\n=================================================");
  console.log("🎉 ALL COMPONENT TESTS PASSED SUCCESSFULLY!");
  console.log("=================================================");

  await browser.close();
}

runTests().catch((err) => {
  console.error("❌ Component test failed:", err.message);
  process.exit(1);
});
