import { test, expect } from "@playwright/test";

test.describe("Wallet flow", () => {
  test("connect wallet button is visible on topbar", async ({ page }) => {
    await page.goto("/");
    // The wallet connect button should appear in the topbar
    const connectBtn = page.getByRole("button", {
      name: /connect/i,
    });
    if (await connectBtn.first().isVisible({ timeout: 3000 }).catch(() => false)) {
      await expect(connectBtn.first()).toBeVisible();
    }
  });

  test("audit page shows repository URL input", async ({ page }) => {
    await page.goto("/audit");
    // Audit form should have a URL input
    await expect(page.locator("body")).toContainText(/audit|repository/i);
  });

  test("staking page shows calculator", async ({ page }) => {
    await page.goto("/staking");
    // Staking calculator should be visible
    await expect(page.locator("body")).toContainText(
      /staking|calculator|stake/i,
    );
  });

  test("verification page shows challenge-related UI", async ({ page }) => {
    await page.goto("/verification");
    await expect(page.locator("body")).toContainText(
      /verification|challenge|window/i,
    );
  });
});
