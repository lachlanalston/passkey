// The phishing twin. Served here from the same origin only so the page itself can be
// exercised — the real deployment must be on a different registrable domain, which is what
// makes attempt 2 fail for the right reason. See phishing-twin/README.md.

import { test, expect } from "@playwright/test";
import { addVirtualAuthenticator, removeAuthenticator, seedMode } from "./helpers.js";

test("the twin is unmistakably labelled as a fake", async ({ page }) => {
  await page.goto("/phishing-twin/index.html");
  await expect(page.locator(".warning-strip")).toHaveText(
    "This is a deliberate fake, built for a training lab. It is not a real sign-in page and it collects nothing.");
  await expect(page.locator('meta[name="robots"]')).toHaveAttribute("content", "noindex, nofollow");
  await expect(page.locator("h1")).toHaveText("Give me your passkey");
});

test("the twin reads the credential ID and real host out of the fragment", async ({ page }) => {
  await page.goto("/phishing-twin/index.html#cred=AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH&rp=passkey.example");
  await expect(page.locator("#real-host")).toHaveText("passkey.example");
  await expect(page.locator("#cred-id")).toContainText("AAAABBBBCCCCDDDDEEEEFFFF");
  await expect(page.locator("#back")).toHaveAttribute("href", "https://passkey.example/");
});

test("the twin gets nothing, and says so", async ({ page }) => {
  const { client, authenticatorId } = await addVirtualAuthenticator(page);
  await page.goto("/phishing-twin/index.html#cred=AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH&rp=passkey.example");

  await page.click("#btn-steal");
  await expect(page.locator(".verdict")).toHaveText(
    "Nothing. The browser wouldn't even offer the passkey here.", { timeout: 20000 });

  const rows = page.locator(".rows .row");
  await expect(rows.nth(0)).toContainText("claim to be passkey.example");
  await expect(rows.nth(0)).toContainText("blocked before any prompt");
  await expect(rows.nth(1)).toContainText("ask honestly, as localhost");
  await expect(rows.nth(1)).toContainText("nothing offered");
  await expect(rows.nth(2)).toContainText("nothing — no key, no signature, no session");

  await expect(page.locator(".cause")).toContainText("A passkey is sealed to the domain it was made on.");
  await removeAuthenticator(client, authenticatorId);
});

test("no twin configured means Step 5 shows only the in-page demo", async ({ page }) => {
  await seedMode(page, "training");
  await page.goto("/index.html");
  await page.evaluate(() => localStorage.setItem("passkey-lab-training", JSON.stringify({
    step: 5, completed: [1, 2, 3, 4], step1CredId: "x", startedAt: "t",
  })));
  await page.reload();

  const twinUrl = await page.evaluate(() => import("/config.js").then((m) => m.TWIN_URL));
  expect(twinUrl).toBe("");                              // not deployed
  await expect(page.locator("#rail-twin")).toHaveCount(0);
  await expect(page.locator("#rail-primary")).toHaveText("Run the phishing attempt");
});
