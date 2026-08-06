// Mode selection — the choice on first visit, that it sticks, and that the masthead
// toggle goes both ways.

import { test, expect } from "@playwright/test";
import { gotoFirstVisit, seedMode } from "./helpers.js";

test("first visit asks which way in, and shows neither bench nor rail", async ({ page }) => {
  await gotoFirstVisit(page);
  await expect(page.locator("#mode-choice")).toBeVisible();
  await expect(page.locator("#bench-view")).toBeHidden();
  await expect(page.locator("#training-view")).toBeHidden();
  await expect(page.locator("#btn-mode")).toBeHidden();

  await expect(page.locator("#landing-title")).toHaveText("Passkey Lab");
  await expect(page.locator(".landing-lede")).toHaveText(
    "See how passkeys actually work — by making one, using one, and watching what happens underneath. Nothing leaves this browser.");
  await expect(page.locator("#btn-mode-training")).toHaveText("Guided lab — make one and see inside");
  await expect(page.locator("#btn-mode-bench")).toHaveText("Open the bench — free-form testing");
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

test("the masthead toggle switches both ways and persists", async ({ page }) => {
  await seedMode(page, "bench");
  await page.goto("/index.html");
  await expect(page.locator("#btn-mode")).toHaveText("Switch to guided lab");

  await page.click("#btn-mode");
  await expect(page.locator("#training-view")).toBeVisible();
  await expect(page.locator("#btn-mode")).toHaveText("Switch to bench");
  expect(await page.evaluate(() => localStorage.getItem("passkey-lab-mode"))).toBe("training");

  await page.click("#btn-mode");
  await expect(page.locator("#bench-view")).toBeVisible();
  await expect(page.locator("#btn-mode")).toHaveText("Switch to guided lab");
  expect(await page.evaluate(() => localStorage.getItem("passkey-lab-mode"))).toBe("bench");
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
