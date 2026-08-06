// Training Mode — the six-step rail. Drives Steps 1 → 2 → 6 end to end against the virtual
// authenticator, plus the locking rules, the InvalidStateError path, the phishing block and
// the reset.

import { test, expect } from "@playwright/test";
import {
  addVirtualAuthenticator, removeAuthenticator, clearCredentials, seedMode,
} from "./helpers.js";

let client, authenticatorId;

test.beforeEach(async ({ page }) => {
  await seedMode(page, "training");
  await page.goto("/index.html");
  await page.evaluate(() => { localStorage.removeItem("passkey-lab-training"); localStorage.removeItem("passkey-lab-creds"); });
  await page.reload();
  ({ client, authenticatorId } = await addVirtualAuthenticator(page));
});

test.afterEach(async () => {
  if (client) await removeAuthenticator(client, authenticatorId).catch(() => {});
});

const stepButton = (page, n) => page.locator(`.stepper-btn[data-goto="${n}"]`);

test("the rail opens on step 1 with everything after it locked", async ({ page }) => {
  await expect(page.locator("#rail-headline")).toHaveText("Make your first passkey");
  await expect(page.locator(".rail-step .eyebrow")).toContainText("Step 1 of 6 · Make your passkey");
  await expect(page.locator("#rail-primary")).toHaveText("Create my passkey");

  await expect(stepButton(page, 1)).toBeEnabled();
  for (const n of [2, 3, 4, 5, 6]) await expect(stepButton(page, n)).toBeDisabled();
});

test("every step carries its Entra connection box", async ({ page }) => {
  await expect(page.locator(".entra-title")).toHaveText("The Entra connection");
  await expect(page.locator(".entra-body")).toContainText(
    "In Microsoft 365 this exact operation runs when a user clicks Security info → Add sign-in method → Passkey");
  await expect(page.locator(".entra-body")).toContainText("Entra just never shows you what got created. Here, you can see it.");
});

test("step 1 creates a passkey, ticks the stepper and unlocks step 2", async ({ page }) => {
  await page.click("#rail-primary");
  await expect(page.locator("#rail-out")).toContainText("Passkey created");
  await expect(page.locator("#rail-out")).toContainText("That's it. Now look underneath.");

  await expect(page.locator('.stepper-item:nth-child(1)')).toHaveClass(/is-done/);
  await expect(stepButton(page, 2)).toBeEnabled();
  await expect(stepButton(page, 3)).toBeDisabled();

  // the ceremony used fixed options, not bench selects — a resident, platform, UV-required key
  const creds = await client.send("WebAuthn.getCredentials", { authenticatorId });
  expect(creds.credentials.length).toBe(1);
  expect(creds.credentials[0].isResidentCredential).toBe(true);

  const record = await page.evaluate(() => JSON.parse(localStorage.getItem("passkey-lab-creds"))[0]);
  expect(record.username).toMatch(/^lab-user-[a-z0-9]{4}$/);
  expect(record.authenticatorAttachment).toBe("platform");
});

test("step 2 times the sign-in and reports the real verification", async ({ page }) => {
  await page.click("#rail-primary");
  await expect(page.locator("#rail-out")).toContainText("Passkey created");
  await page.click('#rail-out button[data-next="2"]');

  await expect(page.locator("#rail-headline")).toHaveText("Sign in with it — and watch the clock");
  await page.click("#rail-primary");
  await expect(page.locator("#rail-out")).toContainText("Signed in — signature verified");
  await expect(page.locator("#rail-out")).toContainText("A texted code averages over a minute.");
  await expect(page.locator("#rail-out")).toContainText("VALID — against the stored public key");
  await expect(page.locator("#rail-out")).toContainText(/\d+\.\d seconds\./);
  await expect(stepButton(page, 3)).toBeEnabled();
});

test("progress survives a reload", async ({ page }) => {
  await page.click("#rail-primary");
  await expect(page.locator("#rail-out")).toContainText("Passkey created");
  await page.click('#rail-out button[data-next="2"]');

  await page.reload();
  await expect(page.locator("#rail-headline")).toHaveText("Sign in with it — and watch the clock");
  await expect(page.locator('.stepper-item:nth-child(1)')).toHaveClass(/is-done/);
  await expect(stepButton(page, 2)).toBeEnabled();
});

test("completed steps stay revisitable, future steps stay locked", async ({ page }) => {
  await page.click("#rail-primary");
  await expect(page.locator("#rail-out")).toContainText("Passkey created");
  await page.click('#rail-out button[data-next="2"]');

  await stepButton(page, 1).click();
  await expect(page.locator("#rail-headline")).toHaveText("Make your first passkey");
  // the result it produced is still there
  await expect(page.locator("#rail-out")).toContainText("Passkey created");

  await expect(stepButton(page, 4)).toBeDisabled();
});

test("step 1 explains the duplicate collision and offers step 6", async ({ page }) => {
  await page.click("#rail-primary");
  await expect(page.locator("#rail-out")).toContainText("Passkey created");

  // Come back to step 1 with the credential still in the authenticator: excludeCredentials
  // makes the browser refuse a second one.
  await stepButton(page, 1).click();
  await page.click("#rail-primary");
  await expect(page.locator("#rail-out")).toContainText("This device already has a passkey for the lab.");
  await expect(page.locator("#rail-out")).toContainText('In Entra this same collision shows up as "a passkey already exists"');
  await expect(page.locator('#rail-out button[data-goto-inline="6"]')).toHaveText("Jump to Step 6");
});

test("step 3 can be skipped, which unlocks step 4 with the walkthrough copy", async ({ page }) => {
  await page.evaluate(() => localStorage.setItem("passkey-lab-training", JSON.stringify({
    step: 3, completed: [1, 2], step1CredId: "x", startedAt: "t",
  })));
  await page.reload();
  await expect(page.locator("#rail-headline")).toHaveText("Do it the way clients will — from a phone");
  await expect(page.locator("#rail-skip")).toHaveText("No phone on you? Skip — you can come back.");

  await page.click("#rail-skip");
  await expect(page.locator("#rail-headline")).toHaveText("Break it — so you recognise the failure");
  await expect(page.locator(".rail-copy")).toContainText("there's no QR flow to break here");
  await expect(page.locator(".rail-check")).toContainText("I read the failure walkthrough");

  await page.check("#rail-check");
  await expect(page.locator('.stepper-item:nth-child(4)')).toHaveClass(/is-done/);
  await expect(stepButton(page, 5)).toBeEnabled();
});

test("step 4 completes on the checkbox and un-completes when it is cleared", async ({ page }) => {
  await page.evaluate(() => localStorage.setItem("passkey-lab-training", JSON.stringify({
    step: 4, completed: [1, 2, 3], step1CredId: "x", step3CredId: "y", startedAt: "t",
  })));
  await page.reload();
  await expect(page.locator(".rail-check")).toContainText("I saw it fail, then fixed it with Bluetooth.");

  await page.check("#rail-check");
  await expect(page.locator('.stepper-item:nth-child(4)')).toHaveClass(/is-done/);

  await page.uncheck("#rail-check");
  await expect(page.locator('.stepper-item:nth-child(4)')).not.toHaveClass(/is-done/);
});

test("step 5 completes on the browser blocking the wrong identity", async ({ page }) => {
  await page.evaluate(() => localStorage.setItem("passkey-lab-training", JSON.stringify({
    step: 5, completed: [1, 2, 3, 4], step1CredId: "x", startedAt: "t",
  })));
  await page.reload();
  await expect(page.locator("#rail-headline")).toHaveText("Try to steal your own passkey");
  await expect(page.locator("#rail-primary")).toHaveText("Run the phishing attempt");

  await page.click("#rail-primary");
  await expect(page.locator("#rail-out .verdict")).toHaveText("Blocked — by the browser, before any prompt");
  await expect(page.locator("#rail-out .phish-wall-label")).toHaveText("Browser refuses");
  await expect(page.locator('.stepper-item:nth-child(5)')).toHaveClass(/is-done/);
});

test("step 6 completes only when the sign-in genuinely fails, and purges the ledger", async ({ page }) => {
  await page.click("#rail-primary");                       // step 1: make one
  await expect(page.locator("#rail-out")).toContainText("Passkey created");
  await page.evaluate(() => {
    const t = JSON.parse(localStorage.getItem("passkey-lab-training"));
    t.step = 6; t.completed = [1, 2, 3, 4, 5];
    localStorage.setItem("passkey-lab-training", JSON.stringify(t));
  });
  await page.reload();
  await expect(page.locator("#rail-headline")).toHaveText("Clean up — lab passkeys are real passkeys");
  await expect(page.locator("#training-view .rail-copy .cleanup-list")).toContainText("Settings → Accounts → Passkeys");
  await expect(page.locator("#training-view .rail-copy .cleanup-list")).toContainText("Google Password Manager");

  // The passkey is still in the device store, so proving it gone must fail.
  await page.click("#rail-primary");
  await expect(page.locator("#rail-out")).toContainText("One still exists — the sign-in worked.");
  await expect(page.locator('.stepper-item:nth-child(6)')).not.toHaveClass(/is-done/);

  // Delete it for real, then prove it.
  await clearCredentials(client, authenticatorId);
  await page.click("#rail-primary");
  await expect(page.locator("#rail-out")).toContainText("Gone. Nothing left for anyone to find, either.");
  await expect(page.locator('.stepper-item:nth-child(6)')).toHaveClass(/is-done/);
  expect(await page.evaluate(() => localStorage.getItem("passkey-lab-creds"))).toBeNull();
});

test("the finish screen appears after step 6 and offers print, bench and reset", async ({ page }) => {
  await page.evaluate(() => localStorage.setItem("passkey-lab-training", JSON.stringify({
    step: 7, completed: [1, 2, 3, 4, 5, 6], startedAt: "t",
  })));
  await page.reload();
  await expect(page.locator(".rail-finish h2")).toHaveText("Lab complete.");
  await expect(page.locator(".rail-lede")).toContainText("That's the part Entra never shows anyone.");
  await expect(page.locator(".rail-keep li").nth(0)).toContainText("The site's identity is sealed into every signature");
  await expect(page.locator(".rail-keep li").nth(1)).toContainText("Cross-device = Bluetooth + internet, on both devices.");
  await expect(page.locator(".rail-keep li").nth(2)).toContainText("Only the public key ever leaves the device");
  await expect(page.locator("#rail-print")).toHaveText("Save/print this page");
  await expect(page.locator("#rail-tobench")).toHaveText("Explore the bench");
  await expect(page.locator("#rail-again")).toHaveText("Reset and go again");

  await page.click("#rail-tobench");
  await expect(page.locator("#bench-view")).toBeVisible();
});

test("reset clears progress after confirming", async ({ page }) => {
  await page.click("#rail-primary");
  await expect(page.locator("#rail-out")).toContainText("Passkey created");

  page.once("dialog", (d) => d.dismiss());
  await page.click("#rail-reset");
  await expect(page.locator('.stepper-item:nth-child(1)')).toHaveClass(/is-done/);

  page.once("dialog", (d) => d.accept());
  await page.click("#rail-reset");
  await expect(page.locator('.stepper-item:nth-child(1)')).not.toHaveClass(/is-done/);
  await expect(page.locator("#rail-headline")).toHaveText("Make your first passkey");
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem("passkey-lab-training")).completed)).toEqual([]);
});

test("rail errors are translated, never raw DOMException names", async ({ page }) => {
  // The rail asks for userVerification "required"; an authenticator that cannot verify the
  // user is refused outright, which is the same NotAllowedError a cancelled prompt raises.
  await removeAuthenticator(client, authenticatorId);
  ({ client, authenticatorId } = await addVirtualAuthenticator(page, {
    hasUserVerification: false, isUserVerified: false,
  }));
  await page.click("#rail-primary");
  await expect(page.locator("#rail-out")).toContainText("You cancelled, or it timed out. No harm done — go again.", { timeout: 20000 });
  await expect(page.locator("#rail-out")).not.toContainText("NotAllowedError");
});

test("step 4 explains the checkbox before you need it, and lays it out on one line", async ({ page }) => {
  await page.evaluate(() => localStorage.setItem("passkey-lab-training", JSON.stringify({
    step: 4, completed: [1, 2, 3], step1CredId: "x", step3CredId: "y", startedAt: "t",
  })));
  await page.reload();

  await expect(page.locator(".rail-check-note")).toHaveText(
    "Running it and watching it fail, then fixing it, completes this step on its own. No phone to hand, or already seen it? Tick the box below instead.");

  // the box sits beside its label, not stacked above it
  const box = await page.locator("#rail-check").boundingBox();
  const label = await page.locator(".rail-check span").boundingBox();
  expect(box.x).toBeLessThan(label.x);
  expect(Math.abs((box.y + box.height / 2) - (label.y + label.height / 2))).toBeLessThan(8);
});

test("the walkthrough variant gets its own checkbox explanation", async ({ page }) => {
  await page.evaluate(() => localStorage.setItem("passkey-lab-training", JSON.stringify({
    step: 4, completed: [1, 2], step1CredId: "x", step3Skipped: true, startedAt: "t",
  })));
  await page.reload();
  await expect(page.locator(".rail-check-note")).toHaveText(
    "Tick the box when you've read it — that completes the step.");
  await expect(page.locator(".rail-check")).toContainText("I read the failure walkthrough");
});

test("step 5 draws the attempt instead of only describing it", async ({ page }) => {
  await page.evaluate(() => localStorage.setItem("passkey-lab-training", JSON.stringify({
    step: 5, completed: [1, 2, 3, 4], step1CredId: "x", startedAt: "t",
  })));
  await page.reload();
  await page.click("#rail-primary");

  const viz = page.locator("#rail-out .phish-viz");
  await expect(viz).toBeVisible();
  await expect(viz.locator(".phish-attacker .phish-domain")).toContainText("attacker-");
  await expect(viz.locator(".phish-wall-label")).toHaveText("Browser refuses");
  await expect(viz.locator(".phish-wall-sub")).toHaveText("before any prompt");
  await expect(viz.locator(".phish-real .phish-domain")).toHaveText("localhost");
  await expect(viz.locator(".phish-real")).toHaveClass(/is-untouched/);

  // the wall sits between the two sides, left to right
  const [atk, wall, real] = await Promise.all(
    [".phish-attacker", ".phish-wall", ".phish-real"].map((s) =>
      viz.locator(s).evaluate((e) => e.getBoundingClientRect().left)));
  expect(wall).toBeGreaterThan(atk);
  expect(real).toBeGreaterThan(wall);

  // and it is described for screen readers, not left as decoration
  await expect(viz).toHaveAttribute("role", "img");
  await expect(viz).toHaveAttribute("aria-label", /never contacted/);
});
