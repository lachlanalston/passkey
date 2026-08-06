// Mode selection — the choice on first visit, that it sticks, and that the masthead nav
// reaches all three sections from any of them.

import { test, expect } from "@playwright/test";
import { gotoFirstVisit, seedMode } from "./helpers.js";

test("first visit asks which way in, and shows neither bench nor rail", async ({ page }) => {
  await gotoFirstVisit(page);
  await expect(page.locator("#mode-choice")).toBeVisible();
  await expect(page.locator("#bench-view")).toBeHidden();
  await expect(page.locator("#training-view")).toBeHidden();

  await expect(page.locator("#landing-title")).toHaveText("Passkey Lab");
  await expect(page.locator(".landing-lede")).toHaveText(
    "See how passkeys actually work — by making one, using one, and watching what happens underneath. Nothing leaves this browser.");
  await expect(page.locator("#btn-mode-training")).toHaveText("Guided lab — make one and see inside");
  await expect(page.locator("#btn-mode-bench")).toHaveText("Open the bench — free-form testing");
});

test("each path is described, not just labelled", async ({ page }) => {
  await gotoFirstVisit(page);
  const cards = page.locator(".landing-card");
  await expect(cards).toHaveCount(2);

  const guided = cards.nth(0);
  await expect(guided.locator(".eyebrow")).toHaveText("Guided lab");
  await expect(guided.locator(".landing-meta")).toHaveText("Six steps · about 10 minutes");
  await expect(guided.locator(".landing-list li")).toHaveCount(6);
  await expect(guided.locator(".landing-list li").first()).toHaveText("Make a real passkey");
  await expect(guided.locator(".landing-list li").last()).toHaveText("Clean up, and prove it's gone");
  await expect(guided.locator(".landing-note")).toContainText("Microsoft Entra");
  await expect(guided.locator("#btn-mode-training")).toBeVisible();

  const bench = cards.nth(1);
  await expect(bench.locator(".eyebrow")).toHaveText("The bench");
  await expect(bench.locator(".landing-meta")).toHaveText("Free-form · nothing locked");
  await expect(bench.locator(".landing-list li")).toHaveCount(5);
  await expect(bench.locator("#btn-mode-bench")).toBeVisible();
});

test("the landing fills the screen instead of trailing off", async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 });
  await gotoFirstVisit(page);
  const bottom = await page.locator("#cleanup-footer").evaluate((el) => el.getBoundingClientRect().bottom);
  expect(bottom).toBeGreaterThan(600);   // was ~360 when it was two bare buttons
  const overflow = await page.evaluate(() =>
    document.documentElement.scrollHeight - window.innerHeight);
  expect(overflow).toBeLessThanOrEqual(0);
});

test("choosing the bench persists across a reload", async ({ page }) => {
  await gotoFirstVisit(page);
  await page.click("#btn-mode-bench");
  await expect(page.locator("#bench-view")).toBeVisible();
  await expect(page.locator("#mode-choice")).toBeHidden();
  expect(await page.evaluate(() => localStorage.getItem("passkey-lab-mode"))).toBe("bench");

  await page.reload();
  await expect(page.locator("#bench-view")).toBeVisible();
  await expect(page.locator("#mode-choice")).toBeHidden();
});

test("choosing the guided lab persists across a reload", async ({ page }) => {
  await gotoFirstVisit(page);
  await page.click("#btn-mode-training");
  await expect(page.locator("#training-view")).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem("passkey-lab-mode"))).toBe("training");

  await page.reload();
  await expect(page.locator("#training-view")).toBeVisible();
  await expect(page.locator("#bench-view")).toBeHidden();
});

const nav = (page, view) => page.locator(`#modenav .modenav-btn[data-view="${view}"]`);

test("the masthead nav reaches all three sections from any of them", async ({ page }) => {
  await seedMode(page, "bench");
  await page.goto("/index.html");
  await expect(nav(page, "choice")).toHaveText("Home");
  await expect(nav(page, "training")).toHaveText("Guided lab");
  await expect(nav(page, "bench")).toHaveText("Bench");

  // bench -> guided lab
  await nav(page, "training").click();
  await expect(page.locator("#training-view")).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem("passkey-lab-mode"))).toBe("training");

  // guided lab -> home
  await nav(page, "choice").click();
  await expect(page.locator("#mode-choice")).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem("passkey-lab-mode"))).toBeNull();

  // home -> bench
  await nav(page, "bench").click();
  await expect(page.locator("#bench-view")).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem("passkey-lab-mode"))).toBe("bench");

  // bench -> home, and straight back to the guided lab
  await nav(page, "choice").click();
  await expect(page.locator("#mode-choice")).toBeVisible();
  await nav(page, "training").click();
  await expect(page.locator("#training-view")).toBeVisible();
});

test("the nav marks where you are, and that item is inert", async ({ page }) => {
  await gotoFirstVisit(page);
  for (const [view, others] of [
    ["choice", ["training", "bench"]],
    ["training", ["choice", "bench"]],
    ["bench", ["choice", "training"]],
  ]) {
    if (view !== "choice") await nav(page, view).click();
    await expect(nav(page, view)).toHaveAttribute("aria-current", "page");
    await expect(nav(page, view)).toBeDisabled();
    for (const o of others) {
      await expect(nav(page, o)).not.toHaveAttribute("aria-current", "page");
      await expect(nav(page, o)).toBeEnabled();
    }
    if (view !== "choice") await nav(page, "choice").click();
  }
});

test("the nav survives a reload on the section you left off in", async ({ page }) => {
  await seedMode(page, "training");
  await page.goto("/index.html");
  await expect(nav(page, "training")).toHaveAttribute("aria-current", "page");
  await page.reload();
  await expect(nav(page, "training")).toHaveAttribute("aria-current", "page");
  await expect(page.locator("#training-view")).toBeVisible();
});

test("the wordmark goes back to the start screen from the bench", async ({ page }) => {
  await seedMode(page, "bench");
  await page.goto("/index.html");
  await expect(page.locator("#bench-view")).toBeVisible();
  await expect(page.locator("#btn-home")).toBeEnabled();

  await page.click("#btn-home");
  await expect(page.locator("#mode-choice")).toBeVisible();
  await expect(page.locator("#bench-view")).toBeHidden();
  expect(await page.evaluate(() => localStorage.getItem("passkey-lab-mode"))).toBeNull();
});

test("the wordmark goes back to the start screen from the guided lab", async ({ page }) => {
  await seedMode(page, "training");
  await page.goto("/index.html");
  await expect(page.locator("#training-view")).toBeVisible();

  await page.click("#btn-home");
  await expect(page.locator("#mode-choice")).toBeVisible();
  await expect(page.locator("#training-view")).toBeHidden();
});

test("the wordmark is inert on the start screen itself", async ({ page }) => {
  await gotoFirstVisit(page);
  await expect(page.locator("#btn-home")).toBeDisabled();
  await expect(page.locator("#btn-home")).toHaveAccessibleName("Passkey Lab");

  await page.click("#btn-mode-bench");
  await expect(page.locator("#btn-home")).toBeEnabled();
  await expect(page.locator("#btn-home")).toHaveAccessibleName("Passkey Lab — back to the start screen");
});

test("going home keeps your place in the guided lab", async ({ page }) => {
  await page.goto("/index.html");
  await page.evaluate(() => {
    localStorage.clear();
    localStorage.setItem("passkey-lab-mode", "training");
    localStorage.setItem("passkey-lab-training", JSON.stringify({ step: 4, completed: [1, 2, 3], startedAt: "t" }));
  });
  await page.reload();

  await page.click("#btn-home");
  await expect(page.locator("#mode-choice")).toBeVisible();
  await expect(page.locator("#btn-mode-training")).toHaveText("Continue the guided lab — step 4 of 6");

  await page.click("#btn-mode-training");
  await expect(page.locator("#rail-headline")).toHaveText("Break it — so you recognise the failure");
});

test("saved progress turns the landing primary into a continue button", async ({ page }) => {
  await page.goto("/index.html");
  await page.evaluate(() => {
    localStorage.clear();
    localStorage.setItem("passkey-lab-training", JSON.stringify({ step: 3, completed: [1, 2], startedAt: 1 }));
  });
  await page.reload();
  await expect(page.locator("#mode-choice")).toBeVisible();
  await expect(page.locator("#btn-mode-training")).toHaveText("Continue the guided lab — step 3 of 6");
});
