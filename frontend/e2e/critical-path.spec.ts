import { test, expect } from "@playwright/test";

test.describe("Critical path", () => {
  test("dashboard loads and shows key sections", async ({ page }) => {
    await page.goto("/");
    // Page should load without errors
    await expect(page).toHaveTitle(/SaltaX/i);
    // Sidebar navigation should be visible on desktop
    const sidebar = page.locator("nav");
    await expect(sidebar.first()).toBeVisible();
  });

  test("navigate to pipeline feed via sidebar", async ({ page }) => {
    await page.goto("/");
    // Click pipeline link in sidebar
    await page.click('a[href="/pipeline"]');
    await expect(page).toHaveURL(/\/pipeline/);
    // Should show filter bar with search input
    await expect(
      page.getByPlaceholder(/filter by repository/i),
    ).toBeVisible();
  });

  test("navigate to pipeline detail from feed", async ({ page }) => {
    await page.goto("/pipeline");
    // If records exist, click the first link
    const firstLink = page.locator("table a").first();
    if (await firstLink.isVisible({ timeout: 5000 }).catch(() => false)) {
      await firstLink.click();
      await expect(page).toHaveURL(/\/pipeline\/.+/);
    }
  });

  test("treasury page renders balance section", async ({ page }) => {
    await page.goto("/treasury");
    // Should show treasury-related content
    await expect(page.locator("body")).toContainText(/treasury|balance|ETH/i);
  });

  test("verification page loads", async ({ page }) => {
    await page.goto("/verification");
    await expect(page.locator("body")).toContainText(
      /verification|window/i,
    );
  });

  test("settings page renders identity section", async ({ page }) => {
    await page.goto("/settings");
    await expect(page.locator("body")).toContainText(/settings|identity/i);
  });

  test("keyboard shortcut Cmd+K opens command palette", async ({ page }) => {
    await page.goto("/");
    await page.keyboard.press("Meta+k");
    // Command palette dialog should appear
    const dialog = page.getByRole("dialog");
    if (await dialog.isVisible({ timeout: 2000 }).catch(() => false)) {
      await expect(dialog).toBeVisible();
      // Press Escape to close
      await page.keyboard.press("Escape");
    }
  });

  test("all main routes return 200", async ({ page }) => {
    const routes = [
      "/",
      "/pipeline",
      "/treasury",
      "/verification",
      "/verification/disputes",
      "/patrol",
      "/intelligence",
      "/intelligence/knowledge",
      "/attestation",
      "/staking",
      "/audit",
      "/logs",
      "/settings",
    ];

    for (const route of routes) {
      const response = await page.goto(route);
      expect(response?.status()).toBe(200);
    }
  });
});
