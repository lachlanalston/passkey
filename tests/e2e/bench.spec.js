// Bench regression — the guarantee that the core-module refactor changed nothing a user
// can see. Covers create, sign-in, autofill, all five prove buttons, the raw inspector,
// export/import and clear.

import { test, expect } from "@playwright/test";
import { addVirtualAuthenticator, removeAuthenticator, trace, gotoFresh } from "./helpers.js";

let client, authenticatorId;

test.beforeEach(async ({ page }) => {
  await gotoFresh(page);
  ({ client, authenticatorId } = await addVirtualAuthenticator(page));
});

test.afterEach(async () => {
  if (client) await removeAuthenticator(client, authenticatorId).catch(() => {});
});

async function createOne(page) {
  await page.click("#btn-create");
  await expect(page.locator("#cred-table tbody tr")).toHaveCount(1);
}

test("create writes a record, a trace entry and an explainer", async ({ page }) => {
  await createOne(page);
  const t = await trace(page);
  expect(t).toContain("navigator.credentials.create() request");
  expect(t).toContain("Passkey created");
  expect(t).toContain('"publicKeyStored": true');
  await expect(page.locator("#explain")).toContainText("The public key is now saved here");
  await expect(page.locator("#cred-table tbody tr td").nth(1)).toHaveText("demo.user@example.com");
});

test("sign-in verifies the real signature", async ({ page }) => {
  await createOne(page);
  await page.click("#btn-auth");
  await expect(page.locator("#log")).toContainText("sign-in verified");
  const t = await trace(page);
  expect(t).toContain('"signatureValid": true');
  expect(t).toContain('"challengeEchoed": true');
  await expect(page.locator("#explain")).toContainText("so this login is genuine and not a replay");
  // sign-in counter on the ledger row ticks
  await expect(page.locator("#cred-table tbody tr td").nth(4)).toHaveText("1");
});

test("sign-in with no stored passkey warns instead of throwing", async ({ page }) => {
  await page.click("#btn-auth");
  await expect(page.locator("#log")).toContainText("no stored passkeys for this site");
  await expect(page.locator("#explain")).toContainText("Create one in step 1 first");
});

test("autofill requests conditional mediation", async ({ page }) => {
  await createOne(page);
  await page.click("#btn-autofill");
  await expect(page.locator("#log")).toContainText("mediation: conditional");
  const t = await trace(page);
  expect(t).toContain("empty → discoverable/any");
});

test("prove: phishing is blocked before any prompt", async ({ page }) => {
  await createOne(page);
  await page.click("#btn-phish");
  await expect(page.locator("#prove-out")).toContainText("Blocked — by the browser, before any prompt");
  // what the credential did (nothing) is now drawn rather than written
  await expect(page.locator("#prove-out .phish-wall-label")).toHaveText("Browser refuses");
  await expect(page.locator("#prove-out .phish-real")).toContainText("Never asked. Never woke up. Never signed.");
  await expect(page.locator("#log")).toContainText("BLOCKED (expected)");
});

test("prove: tamper rejects a flipped byte", async ({ page }) => {
  await createOne(page);
  await page.click("#btn-tamper");
  await expect(page.locator("#prove-out")).toContainText("Integrity verified — tampering rejected");
  await expect(page.locator("#prove-out")).toContainText("INVALID — verification fails");
});

test("prove: replay is caught by the fresh challenge", async ({ page }) => {
  await createOne(page);
  await page.click("#btn-replay");
  await expect(page.locator("#prove-out")).toContainText("Rejected — replay caught");
  await expect(page.locator("#prove-out")).toContainText("VALID — the cryptography is fine");
});

test("prove: only the matching key verifies", async ({ page }) => {
  await createOne(page);
  await page.click("#btn-wrongkey");
  await expect(page.locator("#prove-out")).toContainText("Only the matching key verifies");
  await expect(page.locator("#prove-out")).toContainText("INVALID — verification fails");
});

test("prove: user verification is reported from the real flags", async ({ page }) => {
  await createOne(page);
  await page.click("#btn-uv");
  await expect(page.locator("#prove-out")).toContainText("Accepted — user was verified");
  await expect(page.locator("#prove-out")).toContainText("yes — PIN or biometric checked");
});

test("raw inspector: registration record", async ({ page }) => {
  await createOne(page);
  await page.click("#cred-table button[data-raw]");
  await expect(page.locator("#inspector")).toBeVisible();
  await expect(page.locator("#insp-title")).toHaveText("Raw inspector — registration");
  await expect(page.locator("#insp-body")).toContainText("authenticatorData");
  await expect(page.locator("#insp-body")).toContainText("Attested public key (COSE)");
  await page.keyboard.press("Escape");
  await expect(page.locator("#inspector")).toBeHidden();
});

test("raw inspector: last sign-in re-verifies, and breaks when edited", async ({ page }) => {
  await createOne(page);
  await page.click("#btn-auth");
  await expect(page.locator("#log")).toContainText("sign-in verified");
  await page.click("#btn-inspect");
  await expect(page.locator("#insp-title")).toHaveText("Raw inspector — last sign-in");

  await page.click("#insp-verify");
  await expect(page.locator("#insp-result")).toContainText("VALID");
  await expect(page.locator("#insp-result")).toContainText("message matches what was signed");

  await page.fill("#insp-cd", '{"type":"webauthn.get","challenge":"tampered","origin":"https://evil.example"}');
  await page.click("#insp-verify");
  await expect(page.locator("#insp-result")).toContainText("INVALID");

  await page.click("#insp-reset");
  await page.click("#insp-verify");
  await expect(page.locator("#insp-result")).toContainText("VALID");
  await page.click("#insp-close");
  await expect(page.locator("#inspector")).toBeHidden();
});

test("public key action opens the record card", async ({ page }) => {
  await createOne(page);
  await page.click("#cred-table button[data-key]");
  await expect(page.locator("#insp-title")).toHaveText("Everything the site knows about you");
  await expect(page.locator(".record-card h3")).toHaveText("The server's entire database about you");
  await expect(page.locator(".record-card")).toContainText("-----BEGIN PUBLIC KEY-----");
  await expect(page.locator(".record-card")).toContainText("ES256");
  await expect(page.locator(".record-caption")).toHaveText(
    "No password. No password hash. No secret. Steal this and you can verify signatures — you can't make one.");
  await expect(page.locator("#log")).toContainText("-----BEGIN PUBLIC KEY-----");
  await page.keyboard.press("Escape");
  await expect(page.locator("#inspector")).toBeHidden();
});

test("the record card lists ID, counter, created date and backup state", async ({ page }) => {
  await createOne(page);
  await page.click("#btn-auth");
  await expect(page.locator("#log")).toContainText("sign-in verified");
  await page.click("#cred-table button[data-key]");
  const card = page.locator(".record-card");
  await expect(card).toContainText("Credential ID");
  await expect(card).toContainText("Sign-in counter");
  await expect(card.locator(".prow", { hasText: "Sign-in counter" })).toContainText("1");
  await expect(card).toContainText("Created");
  await expect(card.locator(".prow", { hasText: "Backed up" })).toContainText("no — device-bound");
});

test("the X-ray links through to the record card", async ({ page }) => {
  await createOne(page);
  await page.click("#btn-xray");
  await page.click("#insp-body button[data-xray-record]");
  await expect(page.locator("#insp-title")).toHaveText("Everything the site knows about you");
  await expect(page.locator(".record-card")).toContainText("The server's entire database about you");
});

test("export then import round-trips the ledger", async ({ page }) => {
  await createOne(page);
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.click("#btn-export"),
  ]);
  const path = await download.path();
  await expect(page.locator("#log")).toContainText("Exported credential list to JSON");

  // wipe, then re-import the file just written
  page.once("dialog", (d) => d.accept());
  await page.click("#btn-clear");
  await expect(page.locator("#cred-table tbody tr td.muted")).toHaveText("No passkeys stored yet.");

  await page.setInputFiles("#import-file", path);
  await expect(page.locator("#cred-table tbody tr")).toHaveCount(1);
  await expect(page.locator("#log")).toContainText("Imported 1 new record(s)");
});

test("clear list empties the ledger only after confirming", async ({ page }) => {
  await createOne(page);
  page.once("dialog", (d) => d.dismiss());
  await page.click("#btn-clear");
  await expect(page.locator("#cred-table tbody tr")).toHaveCount(1);

  page.once("dialog", (d) => d.accept());
  await page.click("#btn-clear");
  await expect(page.locator("#cred-table tbody tr td.muted")).toHaveText("No passkeys stored yet.");
  await expect(page.locator("#log")).toContainText("Cleared local passkey list");
});

test("clear log empties the trace and hides the explainer", async ({ page }) => {
  await createOne(page);
  await page.click("#btn-clearlog");
  await expect(page.locator("#log")).toBeEmpty();
  await expect(page.locator("#explain")).toBeHidden();
});

test("no console errors and no network calls beyond the static files", async ({ page }) => {
  const errors = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  const requests = [];
  page.on("request", (r) => requests.push(r.url()));

  await page.reload();
  await createOne(page);
  await page.click("#btn-auth");
  await expect(page.locator("#log")).toContainText("sign-in verified");

  expect(errors).toEqual([]);
  const offSite = requests.filter((u) => !u.startsWith("http://localhost:8000/"));
  expect(offSite).toEqual([]);
});

test("every prove button answers in the same place when there is no passkey", async ({ page }) => {
  // no createOne() — the ledger is empty on purpose
  const cases = [
    ["#btn-tamper", "Tamper test"],
    ["#btn-replay", "Replay test"],
    ["#btn-wrongkey", "Wrong-key test"],
    ["#btn-uv", "User-verification test"],
  ];
  for (const [btn, title] of cases) {
    await page.click(btn);
    await expect(page.locator("#prove-out")).toBeVisible();
    await expect(page.locator("#prove-out .verdict")).toHaveText("Nothing to test yet");
    await expect(page.locator("#prove-out h3")).toHaveText(title);
    await expect(page.locator("#prove-out")).toContainText("Create one in step 1 first");
  }
});

test("a second demo replaces the first verdict instead of leaving it up", async ({ page }) => {
  // The reported bug: phish (which needs no passkey) leaves "Blocked", then tamper appeared
  // to do nothing because it only wrote to the trace.
  await page.click("#btn-phish");
  await expect(page.locator("#prove-out .verdict")).toHaveText("Blocked — by the browser, before any prompt");

  await page.click("#btn-tamper");
  await expect(page.locator("#prove-out .verdict")).toHaveText("Nothing to test yet");
  await expect(page.locator("#prove-out h3")).toHaveText("Tamper test");
  await expect(page.locator("#prove-out")).not.toContainText("Blocked — by the browser");
});

test("the verdict is cleared the moment the next demo starts", async ({ page }) => {
  await createOne(page);
  await page.click("#btn-tamper");
  await expect(page.locator("#prove-out .verdict")).toHaveText("Integrity verified — tampering rejected");

  // Break the demo mid-flight: with no authenticator the get() is refused, and the stale
  // "Integrity verified" must not survive it.
  await removeAuthenticator(client, authenticatorId);
  ({ client, authenticatorId } = await addVirtualAuthenticator(page, {
    hasUserVerification: false, isUserVerified: false,
  }));
  await page.selectOption("#userverification", "required");
  await page.click("#btn-tamper");
  await expect(page.locator("#prove-out .verdict")).toHaveText("Didn't run");
  await expect(page.locator("#prove-out h3")).toHaveText("Tamper test");
  await expect(page.locator("#prove-out")).toContainText("You cancelled, or it timed out");
});

test("each prove button says what attack it runs", async ({ page }) => {
  await expect(page.locator(".prove-lede")).toHaveText(
    "Each button runs a real attack against the passkey you just made — then shows you exactly what stopped it.");

  const expected = [
    ["#btn-phish", "A lookalike domain asks the browser for your passkey."],
    ["#btn-tamper", "One byte of a genuine login is altered in transit."],
    ["#btn-replay", "A real, valid login is captured and sent a second time."],
    ["#btn-wrongkey", "The signature is checked against somebody else's public key."],
    ["#btn-uv", "Did they just touch it, or prove who they are?"],
  ];
  for (const [btn, desc] of expected) {
    const row = page.locator(".prove-list li", { has: page.locator(btn) });
    await expect(row.locator("span")).toHaveText(desc);
    // the description sits beside the button, not under it, at this width
    const b = await page.locator(btn).boundingBox();
    const s = await row.locator("span").boundingBox();
    expect(s.x).toBeGreaterThan(b.x);
  }
});

test("every prove result ties back to Entra", async ({ page }) => {
  await createOne(page);
  const expected = [
    ["#btn-phish", "fake Microsoft 365 login page gets nothing"],
    ["#btn-tamper", "Entra runs this same check on every single sign-in"],
    ["#btn-replay", "login.microsoftonline.com issues a new challenge every time"],
    ["#btn-wrongkey", "Entra stores only this public half"],
    ["#btn-uv", "phishing-resistant MFA policy requires this bit"],
  ];
  for (const [btn, text] of expected) {
    await page.click(btn);
    await expect(page.locator("#prove-out .prove-entra")).toBeVisible();
    await expect(page.locator("#prove-out .prove-entra")).toContainText(text);
  }
});

test("the no-passkey and stopped cards carry no Entra line", async ({ page }) => {
  await page.click("#btn-tamper");                       // empty ledger
  await expect(page.locator("#prove-out .verdict")).toHaveText("Nothing to test yet");
  await expect(page.locator("#prove-out .prove-entra")).toHaveCount(0);
});
