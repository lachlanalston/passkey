// Ceremony X-ray — that it shows the real bytes, the real flags and, above all, the real
// verification result. Node 5 of an authentication X-ray is the one thing in the lab that
// must never be decorative.

import { test, expect } from "@playwright/test";
import { addVirtualAuthenticator, removeAuthenticator, seedMode, gotoFresh } from "./helpers.js";

let client, authenticatorId;

test.afterEach(async () => {
  if (client) await removeAuthenticator(client, authenticatorId).catch(() => {});
  client = null;
});

async function railTo2(page) {
  await seedMode(page, "training");
  await page.goto("/index.html");
  await page.evaluate(() => { localStorage.removeItem("passkey-lab-training"); localStorage.removeItem("passkey-lab-creds"); });
  await page.reload();
  ({ client, authenticatorId } = await addVirtualAuthenticator(page));
  await page.click("#rail-primary");
  await expect(page.locator("#rail-out")).toContainText("Passkey created");
}

test("the registration X-ray shows five nodes, both lanes and the sealed-in identity", async ({ page }) => {
  await railTo2(page);
  const xray = page.locator("#rail-out .xray");
  await expect(xray).toBeVisible();
  await expect(xray).toHaveAttribute("open", "");           // expanded on first occurrence
  await expect(page.locator("#rail-out .xray-node")).toHaveCount(5);

  await expect(xray).toContainText("This site invented a challenge");
  await expect(xray).toContainText("The browser passed the challenge along");
  await expect(xray).toContainText("the site's identity gets sealed in from the very first moment".replace(/^t/, "T"));
  await expect(xray).toContainText("You proved it was you");
  await expect(xray).toContainText("A key pair was made — and only the public half came back");
  await expect(xray).toContainText("This site stored the public key — and nothing else");

  // both persistent badges
  await expect(page.locator("#rail-out .xray-badge")).toHaveCount(2);
  await expect(page.locator("#rail-out .xray-badge").nth(0)).toContainText("Private key — never leaves the authenticator");
  await expect(page.locator("#rail-out .xray-badge").nth(1)).toContainText("Your fingerprint/face — checked inside the device, never transmitted");

  // what crossed the wire is tagged
  await expect(page.locator("#rail-out .xray-wire")).toHaveCount(2);
});

test("the registration X-ray reports the real origin, flags and wallet", async ({ page }) => {
  await railTo2(page);
  const xray = page.locator("#rail-out .xray");
  await expect(xray).toContainText("http://localhost:8000");
  await expect(xray).toContainText("localhost");
  await expect(xray).toContainText("fingerprint, face or PIN checked");   // UV tick, from the real flag
  await expect(xray).toContainText("device-bound");                        // BE/BS from the real flags
});

test("expand raw reuses the inspector's hex and COSE sections", async ({ page }) => {
  await railTo2(page);
  const node4 = page.locator("#rail-out .xray-node").nth(3);
  await node4.locator("summary", { hasText: "expand raw" }).click();
  await expect(node4).toContainText("authenticatorData");
  await expect(node4).toContainText("Attested public key (COSE)");
  await expect(node4).toContainText("AAGUID");
  await expect(node4.locator("pre.hex").first()).toBeVisible();
});

test("the authentication X-ray ends in a real, true verification", async ({ page }) => {
  await railTo2(page);
  await page.click('#rail-out button[data-next="2"]');
  await page.click("#rail-primary");
  await expect(page.locator("#rail-out")).toContainText("Signed in — signature verified");

  const nodes = page.locator("#rail-out .xray-node");
  await expect(nodes).toHaveCount(5);
  await expect(nodes.nth(0)).toContainText("This site invented a new challenge");
  await expect(nodes.nth(1)).toContainText("challenge echoed back");
  await expect(nodes.nth(1)).toContainText("yes — byte for byte");
  await expect(nodes.nth(2)).toContainText("User verified (UV)");
  await expect(nodes.nth(3)).toContainText("sign counter");
  await expect(nodes.nth(4)).toContainText("VALID — the signature matches the stored public key");
});

test("swapping the stored public key makes node 5 report a real failure", async ({ page }) => {
  await railTo2(page);
  await page.click('#rail-out button[data-next="2"]');

  // Replace the stored SPKI with a different, valid P-256 key: same shape, wrong key.
  await page.evaluate(async () => {
    const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const spki = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));
    const b64url = btoa(String.fromCharCode(...spki)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const all = JSON.parse(localStorage.getItem("passkey-lab-creds"));
    all[0].publicKey = b64url;
    localStorage.setItem("passkey-lab-creds", JSON.stringify(all));
  });

  await page.click("#rail-primary");
  const last = page.locator("#rail-out .xray-node").nth(4);
  await expect(last).toContainText("INVALID — a real server would reject this login");
  await expect(last).not.toContainText("VALID — the signature matches");
});

test("an unknown credential says so instead of faking a tick", async ({ page }) => {
  await railTo2(page);
  await page.click('#rail-out button[data-next="2"]');

  // Drop the stored public key: the ceremony still runs, but there is nothing to check against.
  await page.evaluate(() => {
    const all = JSON.parse(localStorage.getItem("passkey-lab-creds"));
    delete all[0].publicKey;
    localStorage.setItem("passkey-lab-creds", JSON.stringify(all));
  });

  await page.click("#rail-primary");
  const last = page.locator("#rail-out .xray-node").nth(4);
  await expect(last).toContainText("Can't verify this one — it predates the X-ray or isn't in the lab's ledger.");
  await expect(last).not.toContainText("VALID");
});

test("the X-ray is two-lane at 1024px and stacked below it, DOM order unchanged", async ({ page }) => {
  await page.setViewportSize({ width: 1400, height: 1000 });
  await railTo2(page);

  const order = await page.locator("#rail-out .xray-node .xray-num").allInnerTexts();
  expect(order).toEqual(["1", "2", "3", "4", "5"]);   // DOM stays chronological

  const lefts = await page.locator("#rail-out .xray-node").evaluateAll(
    (els) => els.map((e) => Math.round(e.getBoundingClientRect().left)));
  expect(lefts[0]).toBe(lefts[1]);          // nodes 1, 2 in the site lane
  expect(lefts[2]).toBe(lefts[3]);          // nodes 3, 4 in the authenticator lane
  expect(lefts[2]).toBeGreaterThan(lefts[0]);
  expect(lefts[4]).toBe(lefts[0]);          // node 5 back in the site lane

  await page.setViewportSize({ width: 900, height: 1000 });
  const stacked = await page.locator("#rail-out .xray-node").evaluateAll(
    (els) => els.map((e) => Math.round(e.getBoundingClientRect().left)));
  expect(new Set(stacked).size).toBe(1);    // one column
});

test("the bench X-ray button renders the same component for the last ceremony", async ({ page }) => {
  await gotoFresh(page);
  ({ client, authenticatorId } = await addVirtualAuthenticator(page));

  await page.click("#btn-xray");
  await expect(page.locator("#explain")).toContainText("Create a passkey or do a Test sign-in first");

  await page.click("#btn-create");
  await expect(page.locator("#cred-table tbody tr")).toHaveCount(1);
  await page.click("#btn-xray");
  await expect(page.locator("#insp-title")).toHaveText("Ceremony X-ray — registration");
  await expect(page.locator("#insp-body .xray-node")).toHaveCount(5);
  await page.keyboard.press("Escape");

  await page.click("#btn-auth");
  await expect(page.locator("#log")).toContainText("sign-in verified");
  await page.click("#btn-xray");
  await expect(page.locator("#insp-title")).toHaveText("Ceremony X-ray — sign-in");
  await expect(page.locator("#insp-body .xray-node").nth(4)).toContainText("VALID — the signature matches the stored public key");
});

test("the X-ray body announces itself politely", async ({ page }) => {
  await railTo2(page);
  await expect(page.locator("#rail-out .xray-body")).toHaveAttribute("aria-live", "polite");
  await expect(page.locator("#rail-out .xray-body .sr-only")).toContainText("Registration ceremony X-ray");
});

test("the five nodes are joined into one path, not five loose cards", async ({ page }) => {
  await page.setViewportSize({ width: 1500, height: 1100 });
  await railTo2(page);

  const shape = await page.locator("#rail-out .xray-node").evaluateAll((els) =>
    els.map((e) => ({
      n: e.querySelector(".xray-num").textContent,
      down: e.classList.contains("connect-down"),
      across: e.classList.contains("connect-across"),
      hasConn: !!e.querySelector(".xray-conn"),
    })));

  // 1→2 same lane, 2→3 crosses, 3→4 same lane, 4→5 crosses, 5 ends
  expect(shape).toEqual([
    { n: "1", down: true, across: false, hasConn: true },
    { n: "2", down: false, across: true, hasConn: true },
    { n: "3", down: true, across: false, hasConn: true },
    { n: "4", down: false, across: true, hasConn: true },
    { n: "5", down: false, across: false, hasConn: false },
  ]);

  // every connector is actually drawn, and none is decorative-only markup
  const drawn = await page.locator("#rail-out .xray-conn").evaluateAll((els) =>
    els.map((e) => { const r = e.getBoundingClientRect(); return r.width > 0 || r.height > 0; }));
  expect(drawn).toEqual([true, true, true, true]);

  // connectors are hidden from assistive tech — the DOM order already carries the sequence
  const hidden = await page.locator("#rail-out .xray-conn").evaluateAll(
    (els) => els.every((e) => e.getAttribute("aria-hidden") === "true"));
  expect(hidden).toBe(true);
});

test("stacked below 1024px, every connector runs straight down", async ({ page }) => {
  await page.setViewportSize({ width: 900, height: 1100 });
  await railTo2(page);
  const vertical = await page.locator("#rail-out .xray-conn").evaluateAll((els) =>
    els.every((e) => { const r = e.getBoundingClientRect(); return r.height > r.width; }));
  expect(vertical).toBe(true);
});

test("the connectors have room to be seen and are not clipped by the next card", async ({ page }) => {
  await page.setViewportSize({ width: 1500, height: 1100 });
  await railTo2(page);

  const geom = await page.evaluate(() => {
    const nodes = [...document.querySelectorAll("#rail-out .xray-node")];
    const rowGap = parseFloat(getComputedStyle(document.querySelector("#rail-out .xray-nodes")).rowGap);
    return nodes.filter((n) => n.querySelector(".xray-conn")).map((n) => {
      const c = n.querySelector(".xray-conn").getBoundingClientRect();
      return { down: n.classList.contains("connect-down"), h: c.height, w: c.width, rowGap };
    });
  });

  for (const g of geom) {
    // the vertical connectors must fit inside the row gap, not run under the next card
    if (g.down) expect(g.h).toBeLessThanOrEqual(g.rowGap);
    expect(g.h + g.w).toBeGreaterThan(20);   // actually drawn, not a hairline
  }
});
