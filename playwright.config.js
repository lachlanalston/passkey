import { defineConfig, devices } from "@playwright/test";

// The lab is a static folder. Serve it exactly the way a person would locally
// (see `npm run serve` / the README one-liner) so the tests exercise the shipped files
// with no build step in between.
export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: false,
  workers: 1,
  reporter: process.env.CI ? "line" : [["list"]],
  use: {
    baseURL: "http://localhost:8000",
    trace: "retain-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
  webServer: {
    command: "python3 -m http.server 8000",
    url: "http://localhost:8000/index.html",
    reuseExistingServer: !process.env.CI,
    stdout: "ignore",
    stderr: "ignore",
  },
});
