// Bench label polish — the humanised option text, the Microsoft mapping in each tooltip,
// and the guided-lab line under the masthead.

import { test, expect } from "@playwright/test";
import { seedMode } from "./helpers.js";

test.beforeEach(async ({ page }) => {
  await seedMode(page, "bench");
  await page.goto("/index.html");
});

test("authenticator options name the thing the tech will actually see", async ({ page }) => {
  const opts = page.locator("#attachment option");
  await expect(opts.nth(0)).toHaveText("Any — browser or wallet chooses");
  await expect(opts.nth(1)).toHaveText("This device (Windows Hello / Touch ID)");
  await expect(opts.nth(2)).toHaveText("Phone or security key (LastPass, YubiKey…)");
});

test("the resident-key field is labelled in English", async ({ page }) => {
  await expect(page.locator("label", { has: page.locator("#residentkey") }).locator(".label-row"))
    .toContainText("Findable by the site (discoverable)");
});

test("every tooltip is a keyboard-reachable disclosure carrying the Microsoft mapping", async ({ page }) => {
  const expected = {
    attachment: 'Shown as “iPhone, iPad or Android device” or “Security key” on Microsoft sign-ins.',
    residentkey: "Lets you sign in with no username typed. Microsoft passkeys work this way.",
    userverification: "Proves who is holding the device, not just that someone touched it. Microsoft requires this.",
    attestation: "Enterprise policy feature — organisations can allow only approved authenticator models. Synced passkeys can’t do this.",
  };

  for (const [id, text] of Object.entries(expected)) {
    const field = page.locator("label", { has: page.locator(`#${id}`) });
    const tip = field.locator("details.tip");
    await expect(tip).toHaveCount(1);
    await expect(tip.locator(".tip-body")).toHaveText(text);

    // closed by default, opens on click, and is not a bare title attribute
    await expect(tip).not.toHaveAttribute("open", "");
    await tip.locator("summary").click();
    await expect(tip).toHaveAttribute("open", "");
    await expect(tip.locator(".tip-body")).toBeVisible();
    await page.locator(".masthead .role").click();   // anywhere inert closes it
    await expect(tip).not.toHaveAttribute("open", "");
  }
});

test("tooltips are named for a screen reader, not just marked with a question mark", async ({ page }) => {
  const summary = page.locator("label", { has: page.locator("#attestation") }).locator("summary");
  await expect(summary.locator(".sr-only")).toHaveText("What “Attestation” means");
});

test("opening a tooltip does not push the form around", async ({ page }) => {
  const before = await page.locator(".b-reg").evaluate((el) => Math.round(el.getBoundingClientRect().height));
  await page.locator("label", { has: page.locator("#attachment") }).locator("summary").click();
  const after = await page.locator(".b-reg").evaluate((el) => Math.round(el.getBoundingClientRect().height));
  expect(after).toBe(before);
});

test("the masthead points newcomers at the guided lab", async ({ page }) => {
  await expect(page.locator(".masthead-note")).toHaveText(
    "New here? The guided lab shows you around — and shows you underneath.");
  await page.click("#btn-tolab");
  await expect(page.locator("#training-view")).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem("passkey-lab-mode"))).toBe("training");
});
