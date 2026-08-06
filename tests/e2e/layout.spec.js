// Layout matrix — the sizes this gets projected at. Asserts column counts, the sticky
// trace, and that nothing ever scrolls sideways or overlaps.

import { test, expect } from "@playwright/test";
import { seedMode } from "./helpers.js";

// Every layout test measures the bench, so skip the first-visit mode choice.
test.beforeEach(async ({ page }) => { await seedMode(page, "bench"); });

const SIZES = [
  { name: "1366x768", width: 1366, height: 768, columns: 2 },
  { name: "1920x1080", width: 1920, height: 1080, columns: 3 },
  { name: "2560x1440", width: 2560, height: 1440, columns: 3 },
  // 1920x1080 at 150% zoom is a 1280px CSS viewport
  { name: "1920x1080 @150%", width: 1280, height: 720, columns: 2 },
  { name: "900x800 (tablet)", width: 900, height: 800, columns: 1 },
  { name: "390x844 (phone)", width: 390, height: 844, columns: 1 },
];

const trackCount = (page, selector) =>
  page.locator(selector).evaluate((el) => getComputedStyle(el).gridTemplateColumns.split(" ").length);

for (const size of SIZES) {
  test(`layout at ${size.name}`, async ({ page }) => {
    await page.setViewportSize({ width: size.width, height: size.height });
    await page.goto("/index.html");

    expect(await trackCount(page, ".bench")).toBe(size.columns);

    // no horizontal scroll anywhere on the page
    const overflow = await page.evaluate(() =>
      document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);

    // no bench panel spills past the frame
    const spills = await page.evaluate(() => {
      const frame = document.querySelector(".frame").getBoundingClientRect();
      return [...document.querySelectorAll(".bench .step, .readout > *")]
        .filter((el) => {
          const r = el.getBoundingClientRect();
          return r.right > frame.right + 1 || r.left < frame.left - 1;
        })
        .map((el) => el.className);
    });
    expect(spills).toEqual([]);

    // no two bench panels overlap
    const overlaps = await page.evaluate(() => {
      const boxes = [...document.querySelectorAll(".bench .step")]
        .map((el) => ({ c: el.className, r: el.getBoundingClientRect() }));
      const hits = [];
      for (let i = 0; i < boxes.length; i++) {
        for (let j = i + 1; j < boxes.length; j++) {
          const a = boxes[i].r, b = boxes[j].r;
          const gapX = a.right <= b.left + 1 || b.right <= a.left + 1;
          const gapY = a.bottom <= b.top + 1 || b.bottom <= a.top + 1;
          if (!gapX && !gapY) hits.push(`${boxes[i].c} / ${boxes[j].c}`);
        }
      }
      return hits;
    });
    expect(overlaps).toEqual([]);
  });
}

test("the whole bench fits on a 1920x1080 screen without scrolling", async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 });

  // Measure the machine this is actually presented from: a laptop with a working built-in
  // authenticator, so no capability notice is raised. Headless Chromium reports no platform
  // authenticator and would raise one, which costs ~60px of height that a presenter never pays.
  await page.addInitScript(() => {
    window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
    window.PublicKeyCredential.isConditionalMediationAvailable = async () => true;
  });
  await page.goto("/index.html");

  // The requirement: every bench panel is on screen at once.
  const benchBottom = await page.locator(".bench").evaluate((el) => el.getBoundingClientRect().bottom);
  expect(benchBottom).toBeLessThanOrEqual(1080);

  // Below the bench sit the cleanup footer and colophon — page furniture, not the bench.
  // Those are allowed to fall past the fold (see IMPLEMENTATION-NOTES N-44); what must not
  // happen is the bench itself needing a scroll, which the assertion above covers.
  const belowBench = await page.evaluate(() => {
    const bench = document.querySelector(".bench").getBoundingClientRect().bottom;
    return document.documentElement.scrollHeight - bench;
  });
  expect(belowBench).toBeLessThan(200);   // furniture only, never another panel
});

test("the trace is sticky and fills its column on a wide screen, static below 1440", async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.goto("/index.html");
  const wide = await page.locator(".step-trace").evaluate((el) => {
    const s = getComputedStyle(el);
    return { position: s.position, top: s.top, maxHeight: s.maxHeight, height: el.getBoundingClientRect().height };
  });
  const benchHeight = await page.locator(".bench").evaluate((el) => el.getBoundingClientRect().height);
  expect(wide.position).toBe("sticky");
  expect(wide.top).toBe("16px");
  expect(wide.maxHeight).toBe("1048px");   // calc(100vh - 2rem)
  expect(wide.height).toBeCloseTo(benchHeight, 0);   // fills the full column

  // When the bench is taller than the screen the trace caps at the viewport and pins.
  await page.setViewportSize({ width: 1920, height: 500 });
  const capped = await page.locator(".step-trace").evaluate((el) => el.getBoundingClientRect().height);
  expect(capped).toBeLessThanOrEqual(500 - 32 + 1);

  await page.setViewportSize({ width: 1366, height: 768 });
  const narrow = await page.locator(".step-trace").evaluate((el) => getComputedStyle(el).position);
  expect(narrow).toBe("static");
});

test("the numbered steps read 01 -> 02 -> 03 in visual order", async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.goto("/index.html");

  // Sort the panels the way an eye scans a grid: down the rows, then across each row.
  const order = await page.evaluate(() =>
    [...document.querySelectorAll(".bench .step")]
      .map((e) => ({ label: e.querySelector(".eyebrow").innerText.replace(/\s+/g, " ").trim(),
                     r: e.getBoundingClientRect() }))
      .sort((a, b) => (a.r.top - b.r.top) || (a.r.left - b.r.left))
      .map((x) => x.label));

  expect(order).toEqual([
    "01 REGISTRATION",
    "02 AUTHENTICATION",
    "TRACE",
    "03 PROVE IT",
    "LEDGER",
  ]);

  const numbered = order.filter((l) => /^\d\d /.test(l));
  expect(numbered).toEqual(["01 REGISTRATION", "02 AUTHENTICATION", "03 PROVE IT"]);
});

test("three columns: steps left and middle, trace in its own full-height column", async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.goto("/index.html");
  const left = (sel) => page.locator(sel).evaluate((el) => Math.round(el.getBoundingClientRect().left));
  const [reg, auth, prove, ledger, trace] = await Promise.all(
    [".b-reg", ".b-auth", ".b-prove", ".b-ledger", ".step-trace"].map(left));
  expect(prove).toBe(reg);              // column 1: registration above prove-it
  expect(ledger).toBe(auth);            // column 2: authentication above the ledger
  expect(auth).toBeGreaterThan(reg);
  expect(trace).toBeGreaterThan(auth);  // column 3: the trace, alone
});

test("the gauges sit five-across under the hero domain on a wide screen", async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.goto("/index.html");
  expect(await trackCount(page, ".gauges")).toBe(5);
  const [leadBottom, gaugesTop] = await Promise.all([
    page.locator(".readout-lead").evaluate((el) => el.getBoundingClientRect().bottom),
    page.locator(".gauges").evaluate((el) => el.getBoundingClientRect().top),
  ]);
  expect(gaugesTop).toBeGreaterThanOrEqual(leadBottom);
});

test("body and log type step up at the wide breakpoint", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await page.goto("/index.html");
  expect(await page.evaluate(() => getComputedStyle(document.body).fontSize)).toBe("15px");

  await page.setViewportSize({ width: 1920, height: 1080 });
  expect(await page.evaluate(() => getComputedStyle(document.body).fontSize)).toBe("16px");
  const logSize = await page.locator("#log").evaluate((el) => parseFloat(getComputedStyle(el).fontSize));
  expect(logSize).toBeCloseTo(12.8, 1);
});

test("panels sit flush in their rows — no hole under a short panel", async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.goto("/index.html");

  const gaps = await page.evaluate(() => {
    const box = (s) => document.querySelector(s).getBoundingClientRect();
    const gap = parseFloat(getComputedStyle(document.querySelector(".bench")).rowGap);
    return {
      gap: Math.round(gap),
      underReg: Math.round(box(".b-prove").top - box(".b-reg").bottom),
      underAuth: Math.round(box(".b-ledger").top - box(".b-auth").bottom),
    };
  });

  // both columns close at the same height, so neither leaves a gap bigger than the grid gap
  expect(gaps.underAuth).toBe(gaps.gap);
  expect(gaps.underReg).toBe(gaps.gap);
});

// Labels wrap to different line counts, so the controls must not follow them around.
for (const width of [2560, 1920, 1600, 1366, 1100]) {
  test(`registration inputs line up at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/index.html");

    const rows = await page.evaluate(() => {
      const ctrls = [...document.querySelectorAll(".b-reg .grid > label")].map((l) => {
        const c = l.querySelector("input, select");
        const r = c.getBoundingClientRect();
        return { id: c.id, top: Math.round(r.top), height: Math.round(r.height) };
      });
      const grouped = {};
      ctrls.forEach((c) => { const k = Math.round(c.top / 40); (grouped[k] ||= []).push(c); });
      return {
        spreads: Object.values(grouped).map((g) => Math.max(...g.map((c) => c.top)) - Math.min(...g.map((c) => c.top))),
        heights: [...new Set(ctrls.map((c) => c.height))],
      };
    });

    for (const s of rows.spreads) expect(s).toBe(0);   // every control in a row starts level
    expect(rows.heights).toHaveLength(1);              // inputs and selects are the same height
  });
}
