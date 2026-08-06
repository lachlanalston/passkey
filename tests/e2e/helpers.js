// Shared Playwright helpers: the CDP virtual authenticator, and small readers for the
// bench's trace pane. Chromium's WebAuthn domain lets the tests answer the platform
// prompt that a human would answer with a fingerprint.

export async function addVirtualAuthenticator(page, overrides = {}) {
  const client = await page.context().newCDPSession(page);
  await client.send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await client.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      ...overrides,
    },
  });
  return { client, authenticatorId };
}

export const getCredentials = (client, authenticatorId) =>
  client.send("WebAuthn.getCredentials", { authenticatorId }).then((r) => r.credentials);

export const clearCredentials = (client, authenticatorId) =>
  client.send("WebAuthn.clearCredentials", { authenticatorId });

export const removeAuthenticator = (client, authenticatorId) =>
  client.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });

export const trace = (page) => page.locator("#log").innerText();

export async function gotoFresh(page, url = "/index.html") {
  await page.goto(url);
  await page.evaluate(() => localStorage.clear());
  await page.reload();
}
