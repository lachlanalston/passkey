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
  await page.goto("/index.html");

  // The requirement: every bench panel is on screen at once.
  const benchBottom = await page.locator(".bench").evaluate((el) => el.getBoundingClientRect().bottom);
  expect(benchBottom).toBeLessThanOrEqual(1080);

  // Stricter, and also true today: the page itself does not scroll at all. Headroom here is
  // thin by construction — see IMPLEMENTATION-NOTES N-44.
  const vertical = await page.evaluate(() =>
    document.documentElement.scrollHeight - window.innerHeight);
  expect(vertical).toBeLessThanOrEqual(0);
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

test("three-column grouping puts registration+auth, prove+ledger and the trace in their own columns", async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.goto("/index.html");
  const left = (sel) => page.locator(sel).evaluate((el) => Math.round(el.getBoundingClientRect().left));
  const [reg, auth, prove, ledger, trace] = await Promise.all(
    [".b-reg", ".b-auth", ".b-prove", ".b-ledger", ".step-trace"].map(left));
  expect(auth).toBe(reg);
  expect(ledger).toBe(prove);
  expect(prove).toBeGreaterThan(reg);
  expect(trace).toBeGreaterThan(prove);
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
