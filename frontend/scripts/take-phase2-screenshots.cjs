const { chromium } = require('playwright');

const JWT_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3ODUxNzM5NDgsInN1YiI6ImVmNDQzMDI5LWRjMjctNDZiMC1iMzZjLWUwZGUzNGFmNmM4MCJ9._RXESZMVFnzGAv3QUhgcxyOsTH-1Rmk3T4MENnRzKDo';

(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } });

  // Inject token into localStorage before any page script runs
  await ctx.addInitScript((token) => {
    localStorage.setItem('sast_token', token);
  }, JWT_TOKEN);

  const page = await ctx.newPage();

  try {
    // Go directly to dashboard
    await page.goto('http://localhost:3000/', { waitUntil: 'domcontentloaded', timeout: 15000 });
    await page.waitForTimeout(4000); // let React + data fetches settle
    console.log('Dashboard URL:', page.url());

    // Full-page dashboard screenshot
    await page.screenshot({ path: 'phase2-screenshots/01-dashboard.png', fullPage: true });
    console.log('Dashboard screenshot saved');

    // Look for project cards — they're divs with cursor-pointer that contain project names
    // Try clicking the first panel that navigates to a project
    const allClickable = await page.$$('div[class*="cursor-pointer"]');
    console.log('cursor-pointer elements:', allClickable.length);

    // Find a project card by looking for panels inside the projects grid
    const projectCard = await page.$('div.grid a, div.grid div[class*="cursor-pointer"]');
    if (projectCard) {
      await projectCard.click();
      await page.waitForTimeout(4000);
      console.log('Project URL:', page.url());
      await page.screenshot({ path: 'phase2-screenshots/02-project.png', fullPage: true });
      console.log('Project screenshot saved');
    } else if (allClickable.length > 0) {
      // Click the last cursor-pointer (project cards are at the end after header buttons)
      await allClickable[allClickable.length - 1].click();
      await page.waitForTimeout(4000);
      console.log('Project URL (fallback):', page.url());
      await page.screenshot({ path: 'phase2-screenshots/02-project.png', fullPage: true });
      console.log('Project screenshot saved (fallback)');
    } else {
      console.log('No project cards found — no projects exist for this user yet');
      // Create a project via API first
    }
  } catch (err) {
    console.error('Error:', err.message);
    try { await page.screenshot({ path: 'phase2-screenshots/error.png', fullPage: true }); } catch {}
  }

  await browser.close();
})();
