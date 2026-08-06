// Cleanup footer — present in both modes, carries the per-OS list, and the Clear-list
// caveat sits where someone about to click Clear list will read it.

import { test, expect } from "@playwright/test";
import { seedMode, gotoFirstVisit } from "./helpers.js";

const OS_LINES = [
  ["Windows", "Settings → Accounts → Passkeys → “Passkey Lab” → delete"],
  ["iPhone/iPad", "Passwords app → search this site → delete"],
  ["Android", "Google Password Manager → search this site → delete"],
  ["Phone passkey from Step 3", "delete on the phone — it lives there"],
  ["LastPass", "it’s a vault item — delete it there"],
];

test("the footer is on the bench, collapsed, with every platform listed", async ({ page }) => {
  await seedMode(page, "bench");
  await page.goto("/index.html");

  const footer = page.locator("#cleanup-footer");
  await expect(footer).toBeVisible();
  await expect(footer).not.toHaveAttribute("open", "");
  await expect(footer.locator("> summary")).toHaveText("Done experimenting? Delete your lab passkeys");

  await footer.locator("> summary").click();
  for (const [label, body] of OS_LINES) {
    const row = footer.locator(".cleanup-os", { hasText: label });
    await expect(row).toContainText(label);
    await expect(row).toContainText(body);
  }
});

test("the footer is on the guided lab too", async ({ page }) => {
  await seedMode(page, "training");
  await page.goto("/index.html");
  await expect(page.locator("#training-view")).toBeVisible();
  await expect(page.locator("#cleanup-footer")).toBeVisible();
});

test("the footer is on the landing screen too", async ({ page }) => {
  await gotoFirstVisit(page);
  await expect(page.locator("#mode-choice")).toBeVisible();
  await expect(page.locator("#cleanup-footer")).toBeVisible();
});

test("the detected platform is the one already open", async ({ page }) => {
  await seedMode(page, "bench");
  await page.goto("/index.html");
  await page.locator("#cleanup-footer > summary").click();
  // The test runner reports a Linux UA, which matches none of the platform entries, so
  // nothing should be forced open. On Windows/macOS/Android the matching one opens.
  const open = await page.locator("#cleanup-footer .cleanup-os[open]").count();
  const ua = await page.evaluate(() => navigator.userAgent);
  expect(open).toBe(/Win|Mac|Android|iPhone|iPad/.test(ua) ? 1 : 0);
});

test("Clear list carries its caveat", async ({ page }) => {
  await seedMode(page, "bench");
  await page.goto("/index.html");
  const caveat = page.locator(".clear-caveat");
  await expect(caveat).toHaveText(
    "clears the lab's records only — the passkey itself stays on your device until you delete it there.");

  // it sits in the same row as the button, where it will actually be read
  const sameRow = await caveat.evaluate((el) =>
    el.parentElement === document.getElementById("btn-clear").parentElement);
  expect(sameRow).toBe(true);
});
