const { chromium } = require("playwright");

(async () => {
  const browser = await chromium.launch({ headless: true, slowMo: 100 });
  const page = await browser.newPage();

  console.log("\n=======================================================");
  console.log(" 🧪 SentinelAI E2E Route Isolation & Auth Test Suite");
  console.log("=======================================================\n");

  let allPassed = true;

  // ---------------------------------------------------------------------------
  // TEST 1: Direct SPA Navigation / Refresh on /projects/... Route
  // ---------------------------------------------------------------------------
  console.log("TEST 1: Direct browser navigation to /projects/demo-123/vulnerabilities/vuln-456...");
  const spaResponse = await page.goto(
    "http://localhost:3000/projects/demo-123/vulnerabilities/vuln-456",
    { waitUntil: "networkidle" }
  );

  const spaStatus = spaResponse.status();
  const contentType = spaResponse.headers()["content-type"] || "";
  console.log(`  Response Status: ${spaStatus}`);
  console.log(`  Content-Type: ${contentType}`);

  if (spaStatus === 200 && contentType.includes("text/html")) {
    console.log("  ✅ SUCCESS: Direct page refresh on /projects/... returned index.html SPA entry point.");
  } else {
    console.error(`  ❌ FAIL: Direct page refresh failed with status ${spaStatus} (Content-Type: ${contentType})`);
    allPassed = false;
  }

  await page.screenshot({ path: "test_screenshots/30_direct_spa_refresh.png", fullPage: true });

  // ---------------------------------------------------------------------------
  // TEST 2: Auth Login Flow via /api/auth/login
  // ---------------------------------------------------------------------------
  console.log("\nTEST 2: Testing Auth Login via /api prefix...");
  await page.goto("http://localhost:3000/", { waitUntil: "networkidle" });

  const inputs = page.locator("input");
  await inputs.nth(0).fill("sentineladmin");
  await inputs.nth(1).fill("Admin1234!");

  // Intercept response to verify request URL includes /api/auth/login
  const [authResponse] = await Promise.all([
    page.waitForResponse((res) => res.url().includes("/api/auth/login"), { timeout: 10000 }),
    page.locator("button[type=submit]").click(),
  ]);

  const authStatus = authResponse.status();
  const authUrl = authResponse.url();
  console.log(`  Auth Request URL: ${authUrl}`);
  console.log(`  Auth Response Status: ${authStatus}`);

  if (authStatus === 200 && authUrl.includes("/api/auth/login")) {
    console.log("  ✅ SUCCESS: Auth login request used /api/auth/login and returned 200 OK.");
  } else {
    console.error(`  ❌ FAIL: Auth login request failed or used wrong endpoint (${authUrl})`);
    allPassed = false;
  }

  await page.waitForTimeout(2000);
  const afterLoginUrl = page.url();
  console.log(`  URL after login: ${afterLoginUrl}`);
  await page.screenshot({ path: "test_screenshots/31_after_login.png", fullPage: true });

  if (afterLoginUrl.includes("/dashboard")) {
    console.log("  ✅ SUCCESS: User redirected to /dashboard after login.");
  }

  console.log("\n=======================================================");
  if (allPassed) {
    console.log("  🎉 ALL TESTS PASSED SUCCESSFULLY!");
  } else {
    console.error("  ⚠️ SOME TESTS FAILED!");
  }
  console.log("=======================================================\n");

  await browser.close();
  if (!allPassed) process.exit(1);
})().catch((err) => {
  console.error("Fatal test error:", err.message);
  process.exit(1);
});
