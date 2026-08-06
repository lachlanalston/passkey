// Capability notices and error translation. The notices are driven by real feature
// detection, so the tests stub the detection APIs before the page script runs.

import { test, expect } from "@playwright/test";
import { addVirtualAuthenticator, removeAuthenticator, seedMode } from "./helpers.js";

async function withCaps(page, { supported = true, platform = true, condui = true, ua = null } = {}) {
  await seedMode(page, "bench");
  await page.addInitScript(({ supported, platform, condui, ua }) => {
    if (!supported) { delete window.PublicKeyCredential; return; }
    window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => platform;
    window.PublicKeyCredential.isConditionalMediationAvailable = async () => condui;
    if (ua) Object.defineProperty(navigator, "userAgent", { get: () => ua });
  }, { supported, platform, condui, ua });
  await page.goto("/index.html");
}

test("a healthy browser gets no notices at all", async ({ page }) => {
  await withCaps(page);
  await expect(page.locator("#notice-reg .notice")).toHaveCount(0);
  await expect(page.locator("#notice-auth .notice")).toHaveCount(0);
  await expect(page.locator("#btn-autofill")).toBeEnabled();
});

test("no WebAuthn support says which browsers have it", async ({ page }) => {
  await withCaps(page, { supported: false });
  await expect(page.locator("#webauthn")).toHaveText("No");
  await expect(page.locator("#notice-reg .notice")).toHaveText(
    "This browser doesn't support passkeys. Chrome, Edge or Safari will.");
  await expect(page.locator("#notice-auth .notice")).toHaveText(
    "This browser doesn't support passkeys. Chrome, Edge or Safari will.");
});

test("no platform authenticator is explained next to the create button", async ({ page }) => {
  await withCaps(page, { platform: false });
  await expect(page.locator("#platform")).toHaveText("Not available");
  await expect(page.locator("#notice-reg .notice")).toHaveText(
    "No built-in authenticator here — you'll be offered a phone or security key instead.");
});

test("Firefox on Linux is told it is a Firefox gap", async ({ page }) => {
  await withCaps(page, { ua: "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0" });
  await expect(page.locator("#notice-reg .notice")).toContainText(
    "Firefox on Linux can't do the phone/QR flow — a Firefox gap, not you. Chrome or Edge can.");
});

test("no conditional mediation disables Autofill and says why", async ({ page }) => {
  await withCaps(page, { condui: false });
  await expect(page.locator("#condui")).toHaveText("Not available");
  await expect(page.locator("#btn-autofill")).toBeDisabled();
  await expect(page.locator("#notice-auth .notice")).toContainText(
    "Autofill sign-in needs conditional mediation, which this browser doesn't offer");
});

test("the bench translates errors and keeps the raw name alongside", async ({ page }) => {
  await seedMode(page, "bench");
  await page.goto("/index.html");
  const { client, authenticatorId } = await addVirtualAuthenticator(page, {
    hasUserVerification: false, isUserVerified: false,
  });
  await page.selectOption("#userverification", "required");
  await page.click("#btn-create");
  await expect(page.locator("#explain")).toContainText("You cancelled, or it timed out. No harm done — go again.");
  await expect(page.locator("#explain")).toContainText("(NotAllowedError)");
  await removeAuthenticator(client, authenticatorId);
});

test("the phishing demo still shows its raw error, because that is the point", async ({ page }) => {
  await seedMode(page, "bench");
  await page.goto("/index.html");
  const { client, authenticatorId } = await addVirtualAuthenticator(page);
  await page.click("#btn-create");
  await expect(page.locator("#cred-table tbody tr")).toHaveCount(1);
  await page.click("#btn-phish");
  await expect(page.locator("#prove-out")).toContainText("Exact error thrown");
  await expect(page.locator("#prove-out")).toContainText("SecurityError");
  await removeAuthenticator(client, authenticatorId);
});

test("the wrong-key test compares against a key of the same algorithm", async ({ page }) => {
  await seedMode(page, "bench");
  await page.goto("/index.html");
  const { client, authenticatorId } = await addVirtualAuthenticator(page);
  await page.click("#btn-create");
  await expect(page.locator("#cred-table tbody tr")).toHaveCount(1);
  await page.click("#btn-wrongkey");
  await expect(page.locator("#prove-out")).toContainText("Only the matching key verifies");
  await expect(page.locator("#prove-out")).toContainText("a fresh ES256 key — same algorithm, different pair");
  await removeAuthenticator(client, authenticatorId);
});
